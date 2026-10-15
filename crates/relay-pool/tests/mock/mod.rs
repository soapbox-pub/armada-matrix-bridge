//! In-process mock relay.
//!
//! With `require_auth`, behaves like ditto-relay: sends an AUTH challenge on
//! connect, keeps a per-connection set of authenticated pubkeys, and closes any
//! REQ whose `authors` are not all authenticated.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use nostr::prelude::*;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_tungstenite::tungstenite::Message;

#[derive(Default)]
pub struct Log {
    /// Every REQ received: (sub id, filters).
    pub reqs: Vec<(String, Vec<Filter>)>,
    /// Pubkeys that authenticated successfully, in order.
    pub authed: Vec<PublicKey>,
    pub connections: usize,
}

pub struct MockRelay {
    pub url: String,
    pub log: Arc<Mutex<Log>>,
    store: Arc<Mutex<Vec<Event>>>,
    live: broadcast::Sender<Event>,
    kill: watch::Sender<u64>,
}

impl MockRelay {
    pub async fn start(require_auth: bool) -> MockRelay {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Log::default()));
        let store = Arc::new(Mutex::new(Vec::new()));
        let (live, _) = broadcast::channel(1024);
        let (kill, _) = watch::channel(0);
        let relay = MockRelay {
            url: url.clone(),
            log: log.clone(),
            store: store.clone(),
            live: live.clone(),
            kill: kill.clone(),
        };
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let ctx = Ctx {
                    url: RelayUrl::parse(&url).unwrap(),
                    require_auth,
                    log: log.clone(),
                    store: store.clone(),
                    live: live.subscribe(),
                    kill: kill.subscribe(),
                    live_tx: live.clone(),
                };
                tokio::spawn(async move {
                    if let Ok(ws) = tokio_tungstenite::accept_async(tcp).await {
                        ctx.serve(ws).await;
                    }
                });
            }
        });
        relay
    }

    pub fn urls(&self) -> Vec<String> {
        vec![self.url.clone()]
    }

    pub fn store(&self, event: Event) {
        self.store.lock().unwrap().push(event);
    }

    /// Store an event and push it to matching live subscriptions.
    pub fn inject(&self, event: Event) {
        self.store(event.clone());
        let _ = self.live.send(event);
    }

    /// Drop every open connection.
    pub fn drop_connections(&self) {
        self.kill.send_modify(|n| *n += 1);
    }

    pub fn reqs_for(&self, sub_id: &str) -> Vec<Vec<Filter>> {
        self.log
            .lock()
            .unwrap()
            .reqs
            .iter()
            .filter(|(id, _)| id == sub_id)
            .map(|(_, f)| f.clone())
            .collect()
    }

    pub fn authed(&self) -> Vec<PublicKey> {
        self.log.lock().unwrap().authed.clone()
    }

    pub fn connections(&self) -> usize {
        self.log.lock().unwrap().connections
    }
}

struct Ctx {
    url: RelayUrl,
    require_auth: bool,
    log: Arc<Mutex<Log>>,
    store: Arc<Mutex<Vec<Event>>>,
    live: broadcast::Receiver<Event>,
    live_tx: broadcast::Sender<Event>,
    kill: watch::Receiver<u64>,
}

fn matches(filters: &[Filter], event: &Event) -> bool {
    filters
        .iter()
        .any(|f| f.match_event(event, MatchEventOptions::default()))
}

impl Ctx {
    async fn serve(mut self, ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) {
        self.log.lock().unwrap().connections += 1;
        let (mut sink, mut stream) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
        let writer = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                if sink.send(Message::Text(msg.into())).await.is_err() {
                    break;
                }
            }
        });
        let send = |m: RelayMessage<'_>| {
            let _ = out_tx.send(m.as_json());
        };

        let challenge = SubscriptionId::generate().to_string();
        if self.require_auth {
            send(RelayMessage::auth(challenge.clone()));
        }
        let mut authed: HashSet<PublicKey> = HashSet::new();
        let mut subs: HashMap<String, Vec<Filter>> = HashMap::new();
        self.kill.mark_unchanged();

        loop {
            tokio::select! {
                _ = self.kill.changed() => break,
                ev = self.live.recv() => {
                    let Ok(ev) = ev else { continue };
                    for (id, filters) in &subs {
                        if matches(filters, &ev) {
                            send(RelayMessage::event(SubscriptionId::new(id), ev.clone()));
                        }
                    }
                }
                msg = stream.next() => {
                    let Some(Ok(msg)) = msg else { break };
                    let Message::Text(text) = msg else { continue };
                    let Ok(cmsg) = ClientMessage::from_json(text.as_str()) else {
                        send(RelayMessage::notice("bad message"));
                        continue;
                    };
                    match cmsg {
                        ClientMessage::Auth(event) => {
                            let ok = event.verify().is_ok()
                                && nip42::is_valid_auth_event(&event, &self.url, &challenge);
                            if ok {
                                authed.insert(event.pubkey);
                                self.log.lock().unwrap().authed.push(event.pubkey);
                                send(RelayMessage::ok(event.id, true, ""));
                            } else {
                                send(RelayMessage::ok(event.id, false, "invalid: bad auth"));
                            }
                        }
                        ClientMessage::Req { subscription_id, filters } => {
                            let id = subscription_id.to_string();
                            let filters: Vec<Filter> = filters.into_iter().map(|f| f.into_owned()).collect();
                            self.log.lock().unwrap().reqs.push((id.clone(), filters.clone()));
                            if self.require_auth {
                                let all_authed = filters.iter().all(|f| {
                                    f.authors.as_ref().is_none_or(|a| a.iter().all(|pk| authed.contains(pk)))
                                });
                                if !all_authed {
                                    subs.remove(&id);
                                    send(RelayMessage::closed(
                                        SubscriptionId::new(&id),
                                        "auth-required: all authors must be authenticated",
                                    ));
                                    continue;
                                }
                            }
                            let stored: Vec<Event> = self.store.lock().unwrap().clone();
                            for ev in stored.into_iter().filter(|e| matches(&filters, e)) {
                                send(RelayMessage::event(SubscriptionId::new(&id), ev));
                            }
                            send(RelayMessage::eose(SubscriptionId::new(&id)));
                            subs.insert(id, filters);
                        }
                        ClientMessage::Close(id) => {
                            subs.remove(id.as_str());
                        }
                        ClientMessage::Event(event) => {
                            let event = event.into_owned();
                            if self.require_auth && !authed.contains(&event.pubkey) {
                                send(RelayMessage::ok(event.id, false, "ERROR: auth-required: sign in first"));
                            } else if event.content == "reject" {
                                send(RelayMessage::ok(event.id, false, "blocked: nope"));
                            } else {
                                send(RelayMessage::ok(event.id, true, ""));
                                self.store.lock().unwrap().push(event.clone());
                                let _ = self.live_tx.send(event);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        writer.abort();
    }
}
