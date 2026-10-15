//! The per-relay connection task.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr::prelude::*;
use rand::Rng;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::Shared;

/// Relay messages larger than this are ignored.
const MAX_MESSAGE_SIZE: usize = 1 << 20;
/// Hard limit enforced by the websocket layer; exceeding it drops the connection.
const MAX_WS_MESSAGE_SIZE: usize = 16 << 20;
const PING_INTERVAL: Duration = Duration::from_secs(30);
const DEAD_AFTER: Duration = Duration::from_secs(90);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A connection that lived at least this long resets the backoff.
const STABLE_CONNECTION: Duration = Duration::from_secs(10);
/// How far before the newest seen event a resubscription starts.
const SINCE_OVERLAP_SECS: u64 = 60;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub(crate) enum Cmd {
    Subscribe {
        sub_id: String,
        filters: Vec<Filter>,
    },
    Unsubscribe {
        sub_id: String,
    },
    Query {
        id: SubscriptionId,
        filters: Vec<Filter>,
        tx: mpsc::UnboundedSender<QueryMsg>,
    },
    CancelQuery {
        id: SubscriptionId,
    },
    Publish {
        event: Box<Event>,
        tx: oneshot::Sender<Result<(), String>>,
    },
    CancelPublish {
        id: EventId,
    },
    AuthKeysChanged,
}

pub(crate) enum QueryMsg {
    Event(Box<Event>),
    /// The relay is done with this query (EOSE, CLOSED, or unreachable).
    Done,
}

struct RelaySub {
    filters: Vec<Filter>,
    newest: Option<Timestamp>,
    sent_epoch: u64,
    awaiting_auth: bool,
}

struct PendingQuery {
    filters: Vec<Filter>,
    tx: mpsc::UnboundedSender<QueryMsg>,
    sent_epoch: u64,
    retried: bool,
    awaiting_auth: Option<String>,
}

struct PendingPublish {
    event: Box<Event>,
    txs: Vec<oneshot::Sender<Result<(), String>>>,
    sent_epoch: u64,
    retried: bool,
    awaiting_auth: Option<String>,
}

/// NIP-42 state of one connection.
#[derive(Default)]
struct Conn {
    challenge: Option<String>,
    pending: HashMap<EventId, PublicKey>,
    acked: HashSet<PublicKey>,
    rejected: HashSet<PublicKey>,
    /// Bumped whenever the relay accepts an AUTH. A request sent at an older
    /// epoch that came back `auth-required` is worth re-sending.
    epoch: u64,
}

enum Outcome {
    Disconnected,
    Exit,
}

struct RelayTask {
    shared: Arc<Shared>,
    url: String,
    rx: mpsc::UnboundedReceiver<Cmd>,
    subs: HashMap<String, RelaySub>,
    queries: HashMap<SubscriptionId, PendingQuery>,
    publishes: HashMap<EventId, PendingPublish>,
    conn: Option<Conn>,
    out: Vec<String>,
}

pub(crate) async fn run(shared: Arc<Shared>, url: String, rx: mpsc::UnboundedReceiver<Cmd>) {
    RelayTask {
        shared,
        url,
        rx,
        subs: HashMap::new(),
        queries: HashMap::new(),
        publishes: HashMap::new(),
        conn: None,
        out: Vec::new(),
    }
    .run()
    .await
}

/// Whether a relay's OK/CLOSED reason asks for authentication. Accepts
/// prefixed reasons such as `ERROR: auth-required: ...`.
pub(crate) fn is_auth_required(reason: &str) -> bool {
    reason.starts_with("auth-required:")
        || reason == "auth-required"
        || reason.contains(": auth-required:")
}

fn tls_connector() -> Connector {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(config)
    });
    Connector::Rustls(config.clone())
}

fn jitter(d: Duration) -> Duration {
    let extra = rand::thread_rng().gen_range(0.0..0.5);
    d.mul_f64(1.0 + extra)
}

impl RelayTask {
    async fn run(mut self) {
        let mut backoff = BACKOFF_MIN;
        let mut idle_since = Instant::now();
        loop {
            while !self.has_work() {
                match tokio::time::timeout_at(idle_since + IDLE_TIMEOUT, self.rx.recv()).await {
                    Ok(Some(cmd)) => self.handle_cmd(cmd),
                    Ok(None) => return,
                    Err(_) => {
                        if self.try_exit() {
                            return;
                        }
                        idle_since = Instant::now();
                    }
                }
            }

            match self.connect().await {
                Ok(ws) => {
                    let started = Instant::now();
                    self.conn = Some(Conn::default());
                    self.shared.set_connected(&self.url, true);
                    let outcome = self.run_connection(ws).await;
                    self.on_disconnect();
                    if let Outcome::Exit = outcome {
                        return;
                    }
                    if started.elapsed() >= STABLE_CONNECTION {
                        backoff = BACKOFF_MIN;
                    }
                }
                Err(e) => {
                    tracing::warn!(relay = %self.url, error = %e, "relay connection failed");
                    self.fail_pending(&format!("connection failed: {e}"));
                }
            }

            if !self.has_work() {
                idle_since = Instant::now();
                continue;
            }
            let deadline = Instant::now() + jitter(backoff);
            backoff = (backoff * 2).min(BACKOFF_MAX);
            loop {
                tokio::select! {
                    cmd = self.rx.recv() => match cmd {
                        Some(cmd) => self.handle_cmd(cmd),
                        None => return,
                    },
                    _ = tokio::time::sleep_until(deadline) => break,
                }
            }
        }
    }

    async fn connect(&self) -> Result<Ws, String> {
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
            .max_frame_size(Some(MAX_WS_MESSAGE_SIZE));
        let connector = if self.url.starts_with("wss://") {
            tls_connector()
        } else {
            Connector::Plain
        };
        let fut = tokio_tungstenite::connect_async_tls_with_config(
            self.url.as_str(),
            Some(config),
            true,
            Some(connector),
        );
        match tokio::time::timeout(CONNECT_TIMEOUT, fut).await {
            Ok(Ok((ws, _))) => Ok(ws),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("timed out".to_string()),
        }
    }

    async fn run_connection(&mut self, mut ws: Ws) -> Outcome {
        enum Ev {
            Cmd(Option<Cmd>),
            Ws(Option<Result<Message, tokio_tungstenite::tungstenite::Error>>),
            Tick,
        }

        tracing::debug!(relay = %self.url, "connected");
        self.resend_all();
        let mut last_rx = Instant::now();
        let mut idle_since: Option<Instant> = None;
        let mut tick = tokio::time::interval_at(Instant::now() + PING_INTERVAL, PING_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            for msg in std::mem::take(&mut self.out) {
                if let Err(e) = ws.send(Message::Text(msg.into())).await {
                    tracing::debug!(relay = %self.url, error = %e, "send failed");
                    return Outcome::Disconnected;
                }
            }

            let ev = tokio::select! {
                cmd = self.rx.recv() => Ev::Cmd(cmd),
                msg = ws.next() => Ev::Ws(msg),
                _ = tick.tick() => Ev::Tick,
            };

            match ev {
                Ev::Cmd(Some(cmd)) => self.handle_cmd(cmd),
                Ev::Cmd(None) => {
                    let _ = ws.close(None).await;
                    return Outcome::Exit;
                }
                Ev::Ws(Some(Ok(msg))) => {
                    last_rx = Instant::now();
                    match msg {
                        Message::Text(text) => self.handle_text(text.as_str()),
                        Message::Close(_) => return Outcome::Disconnected,
                        _ => {}
                    }
                }
                Ev::Ws(Some(Err(e))) => {
                    tracing::debug!(relay = %self.url, error = %e, "websocket error");
                    return Outcome::Disconnected;
                }
                Ev::Ws(None) => return Outcome::Disconnected,
                Ev::Tick => {
                    if last_rx.elapsed() >= DEAD_AFTER {
                        tracing::warn!(relay = %self.url, "relay silent, reconnecting");
                        return Outcome::Disconnected;
                    }
                    if ws.send(Message::Ping(Default::default())).await.is_err() {
                        return Outcome::Disconnected;
                    }
                    if self.has_work() {
                        idle_since = None;
                    } else if idle_since.get_or_insert_with(Instant::now).elapsed() >= IDLE_TIMEOUT
                        && self.try_exit()
                    {
                        let _ = ws.close(None).await;
                        return Outcome::Exit;
                    }
                }
            }
        }
    }

    fn has_work(&self) -> bool {
        !self.subs.is_empty() || !self.queries.is_empty() || !self.publishes.is_empty()
    }

    /// Unregister this task if no command is waiting. Returns whether it did.
    fn try_exit(&mut self) -> bool {
        let shared = self.shared.clone();
        let cmd = {
            let mut st = shared.lock();
            match self.rx.try_recv() {
                Ok(cmd) => cmd,
                Err(_) => {
                    st.relays.remove(&self.url);
                    tracing::debug!(relay = %self.url, "closing idle relay");
                    return true;
                }
            }
        };
        self.handle_cmd(cmd);
        false
    }

    fn on_disconnect(&mut self) {
        self.conn = None;
        self.out.clear();
        for sub in self.subs.values_mut() {
            sub.awaiting_auth = false;
        }
        for q in self.queries.values_mut() {
            q.awaiting_auth = None;
        }
        for p in self.publishes.values_mut() {
            p.awaiting_auth = None;
        }
        self.shared.set_connected(&self.url, false);
        tracing::debug!(relay = %self.url, "disconnected");
    }

    fn fail_pending(&mut self, reason: &str) {
        for (_, q) in self.queries.drain() {
            let _ = q.tx.send(QueryMsg::Done);
        }
        for (_, p) in self.publishes.drain() {
            for tx in p.txs {
                let _ = tx.send(Err(reason.to_string()));
            }
        }
    }

    fn epoch(&self) -> u64 {
        self.conn.as_ref().map_or(0, |c| c.epoch)
    }

    fn push(&mut self, msg: ClientMessage<'_>) {
        if self.conn.is_some() {
            self.out.push(msg.as_json());
        }
    }

    fn resend_all(&mut self) {
        let subs: Vec<String> = self.subs.keys().cloned().collect();
        for id in subs {
            self.send_sub(&id);
        }
        let queries: Vec<SubscriptionId> = self.queries.keys().cloned().collect();
        for id in queries {
            self.send_query(&id);
        }
        let publishes: Vec<EventId> = self.publishes.keys().copied().collect();
        for id in publishes {
            self.send_publish(&id);
        }
    }

    fn send_sub(&mut self, sub_id: &str) {
        if self.conn.is_none() {
            return;
        }
        let epoch = self.epoch();
        let Some(sub) = self.subs.get_mut(sub_id) else {
            return;
        };
        sub.sent_epoch = epoch;
        let filters = match sub.newest {
            None => sub.filters.clone(),
            Some(newest) => {
                let floor =
                    Timestamp::from_secs(newest.as_secs().saturating_sub(SINCE_OVERLAP_SECS));
                sub.filters
                    .iter()
                    .cloned()
                    .map(|mut f| {
                        f.since = Some(f.since.map_or(floor, |s| s.max(floor)));
                        f
                    })
                    .collect()
            }
        };
        self.push(ClientMessage::req(SubscriptionId::new(sub_id), filters));
    }

    fn send_query(&mut self, id: &SubscriptionId) {
        if self.conn.is_none() {
            return;
        }
        let epoch = self.epoch();
        let Some(q) = self.queries.get_mut(id) else {
            return;
        };
        q.sent_epoch = epoch;
        let msg = ClientMessage::req(id.clone(), q.filters.clone());
        self.push(msg);
    }

    fn send_publish(&mut self, id: &EventId) {
        if self.conn.is_none() {
            return;
        }
        let epoch = self.epoch();
        let Some(p) = self.publishes.get_mut(id) else {
            return;
        };
        p.sent_epoch = epoch;
        let msg = ClientMessage::event((*p.event).clone());
        self.push(msg);
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Subscribe { sub_id, filters } => {
                let sub = self.subs.entry(sub_id.clone()).or_insert_with(|| RelaySub {
                    filters: Vec::new(),
                    newest: None,
                    sent_epoch: 0,
                    awaiting_auth: false,
                });
                if sub.filters != filters {
                    sub.filters = filters;
                    sub.newest = None;
                }
                sub.awaiting_auth = false;
                self.send_sub(&sub_id);
            }
            Cmd::Unsubscribe { sub_id } => {
                if self.subs.remove(&sub_id).is_some() {
                    self.push(ClientMessage::close(SubscriptionId::new(sub_id)));
                }
            }
            Cmd::Query { id, filters, tx } => {
                self.queries.insert(
                    id.clone(),
                    PendingQuery {
                        filters,
                        tx,
                        sent_epoch: 0,
                        retried: false,
                        awaiting_auth: None,
                    },
                );
                self.send_query(&id);
            }
            Cmd::CancelQuery { id } => {
                if self.queries.remove(&id).is_some() {
                    self.push(ClientMessage::close(id));
                }
            }
            Cmd::Publish { event, tx } => {
                let id = event.id;
                if let Some(p) = self.publishes.get_mut(&id) {
                    p.txs.push(tx);
                    return;
                }
                self.publishes.insert(
                    id,
                    PendingPublish {
                        event,
                        txs: vec![tx],
                        sent_epoch: 0,
                        retried: false,
                        awaiting_auth: None,
                    },
                );
                self.send_publish(&id);
            }
            Cmd::CancelPublish { id } => {
                if let Some(p) = self.publishes.get_mut(&id) {
                    p.txs.retain(|tx| !tx.is_closed());
                    if p.txs.is_empty() {
                        self.publishes.remove(&id);
                    }
                }
            }
            Cmd::AuthKeysChanged => {
                self.send_auths();
                self.check_awaiting();
            }
        }
    }

    fn handle_text(&mut self, text: &str) {
        if text.len() > MAX_MESSAGE_SIZE {
            tracing::warn!(relay = %self.url, len = text.len(), "ignoring oversized message");
            return;
        }
        let msg = match RelayMessage::from_json(text) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::debug!(relay = %self.url, error = %e, "ignoring malformed message");
                return;
            }
        };
        match msg {
            RelayMessage::Event {
                subscription_id,
                event,
            } => self.on_event(&subscription_id, event.into_owned()),
            RelayMessage::Ok {
                event_id,
                status,
                message,
            } => self.on_ok(event_id, status, &message),
            RelayMessage::EndOfStoredEvents(id) => self.on_eose(&id),
            RelayMessage::Closed {
                subscription_id,
                message,
            } => self.on_closed(&subscription_id, &message),
            RelayMessage::Notice(message) => {
                tracing::info!(relay = %self.url, %message, "relay notice");
            }
            RelayMessage::Auth { challenge } => self.on_challenge(challenge.into_owned()),
            _ => {}
        }
    }

    fn on_event(&mut self, id: &SubscriptionId, event: Event) {
        if let Some(sub) = self.subs.get_mut(id.as_str()) {
            if sub.newest.is_none_or(|n| event.created_at > n) {
                sub.newest = Some(event.created_at);
            }
            self.shared.deliver(&self.url, id.as_str(), event);
        } else if let Some(q) = self.queries.get(id) {
            let _ = q.tx.send(QueryMsg::Event(Box::new(event)));
        }
    }

    fn on_eose(&mut self, id: &SubscriptionId) {
        if self.subs.contains_key(id.as_str()) {
            self.shared.emit(crate::PoolEvent::Eose {
                relay: self.url.clone(),
                sub_id: id.to_string(),
            });
        } else if let Some(q) = self.queries.remove(id) {
            let _ = q.tx.send(QueryMsg::Done);
            self.push(ClientMessage::close(id.clone()));
        }
    }

    fn on_closed(&mut self, id: &SubscriptionId, reason: &str) {
        let auth = is_auth_required(reason);
        if let Some(sub) = self.subs.get_mut(id.as_str()) {
            if auth {
                tracing::debug!(relay = %self.url, sub = %id, %reason, "subscription needs auth");
                sub.awaiting_auth = true;
            } else {
                tracing::warn!(relay = %self.url, sub = %id, %reason, "subscription closed by relay");
                self.subs.remove(id.as_str());
                return;
            }
        } else if let Some(q) = self.queries.get_mut(id) {
            if auth && !q.retried {
                q.awaiting_auth = Some(reason.to_string());
            } else {
                tracing::debug!(relay = %self.url, %reason, "query closed by relay");
                if let Some(q) = self.queries.remove(id) {
                    let _ = q.tx.send(QueryMsg::Done);
                }
                return;
            }
        } else {
            return;
        }
        self.send_auths();
        self.check_awaiting();
    }

    fn on_ok(&mut self, id: EventId, status: bool, reason: &str) {
        if let Some(conn) = &mut self.conn
            && let Some(pk) = conn.pending.remove(&id)
        {
            if status {
                tracing::debug!(relay = %self.url, pubkey = %pk, "authenticated");
                conn.acked.insert(pk);
                conn.epoch += 1;
            } else {
                tracing::warn!(relay = %self.url, pubkey = %pk, %reason, "AUTH rejected");
                conn.rejected.insert(pk);
            }
            self.check_awaiting();
            return;
        }

        let Some(p) = self.publishes.get_mut(&id) else {
            return;
        };
        if status {
            if let Some(p) = self.publishes.remove(&id) {
                for tx in p.txs {
                    let _ = tx.send(Ok(()));
                }
            }
        } else if is_auth_required(reason) && !p.retried {
            p.awaiting_auth = Some(reason.to_string());
            self.send_auths();
            self.check_awaiting();
        } else if let Some(p) = self.publishes.remove(&id) {
            for tx in p.txs {
                let _ = tx.send(Err(reason.to_string()));
            }
        }
    }

    fn on_challenge(&mut self, challenge: String) {
        let Some(conn) = &mut self.conn else {
            return;
        };
        if conn.challenge.as_deref() != Some(challenge.as_str()) {
            let epoch = conn.epoch;
            *conn = Conn {
                challenge: Some(challenge),
                epoch,
                ..Conn::default()
            };
        }
        self.send_auths();
        self.check_awaiting();
    }

    /// Send AUTH for every in-scope key not yet sent on this connection.
    fn send_auths(&mut self) {
        let Some(challenge) = self.conn.as_ref().and_then(|c| c.challenge.clone()) else {
            return;
        };
        let keys = self.shared.keys_for(&self.url);
        let Some(conn) = &mut self.conn else {
            return;
        };
        let mut sent = HashSet::new();
        for keys in keys {
            let pk = keys.public_key();
            if conn.acked.contains(&pk)
                || conn.rejected.contains(&pk)
                || conn.pending.values().any(|p| *p == pk)
                || !sent.insert(pk)
            {
                continue;
            }
            let event = EventBuilder::new(Kind::Authentication, "")
                .tags([
                    Tag::custom("relay", [self.url.as_str()]),
                    Tag::custom("challenge", [challenge.as_str()]),
                ])
                .finalize(&keys);
            match event {
                Ok(event) => {
                    conn.pending.insert(event.id, pk);
                    self.out.push(ClientMessage::auth(event).as_json());
                }
                Err(e) => tracing::warn!(relay = %self.url, error = %e, "failed to sign AUTH"),
            }
        }
    }

    /// Once no AUTH is in flight, re-send requests the relay closed for
    /// auth-required if some key was accepted since they were sent; give up on
    /// one-shot requests that can make no further progress.
    fn check_awaiting(&mut self) {
        let Some(conn) = &self.conn else {
            return;
        };
        if conn.challenge.is_none() || !conn.pending.is_empty() {
            return;
        }
        let epoch = conn.epoch;

        let subs: Vec<String> = self
            .subs
            .iter_mut()
            .filter(|(_, s)| s.awaiting_auth && s.sent_epoch < epoch)
            .map(|(id, s)| {
                s.awaiting_auth = false;
                id.clone()
            })
            .collect();
        for id in subs {
            self.send_sub(&id);
        }

        let mut retry = Vec::new();
        let mut give_up = Vec::new();
        for (id, q) in &mut self.queries {
            if q.awaiting_auth.take().is_some() {
                if q.sent_epoch < epoch {
                    q.retried = true;
                    retry.push(id.clone());
                } else {
                    give_up.push(id.clone());
                }
            }
        }
        for id in retry {
            self.send_query(&id);
        }
        for id in give_up {
            if let Some(q) = self.queries.remove(&id) {
                let _ = q.tx.send(QueryMsg::Done);
            }
        }

        let mut retry = Vec::new();
        let mut give_up = Vec::new();
        for (id, p) in &mut self.publishes {
            if let Some(reason) = p.awaiting_auth.take() {
                if p.sent_epoch < epoch {
                    p.retried = true;
                    retry.push(*id);
                } else {
                    give_up.push((*id, reason));
                }
            }
        }
        for id in retry {
            self.send_publish(&id);
        }
        for (id, reason) in give_up {
            if let Some(p) = self.publishes.remove(&id) {
                for tx in p.txs {
                    let _ = tx.send(Err(reason.clone()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_auth_required;

    #[test]
    fn auth_required_prefixes() {
        assert!(is_auth_required("auth-required: please"));
        assert!(is_auth_required("auth-required"));
        assert!(is_auth_required("ERROR: auth-required: please"));
        assert!(!is_auth_required(
            "blocked: auth-required is not the reason"
        ));
        assert!(!is_auth_required("restricted: no"));
    }
}
