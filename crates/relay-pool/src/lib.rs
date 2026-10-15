//! A Nostr relay pool built for the Matrix <-> Armada (Concord) bridge.
//!
//! Concord events are kind-1059 gift wraps authored by many derived "stream
//! keys". Relays such as ditto-relay only serve those events to a connection
//! that has authenticated (NIP-42) as *every* pubkey listed in a REQ's
//! `authors`. The pool therefore answers each AUTH challenge with one kind-22242
//! event signed by the main key plus one per registered stream key whose relay
//! scope covers that relay, and re-sends requests the relay closed with
//! `auth-required` once new keys have been accepted.
//!
//! Each relay gets one connection task that reconnects with exponential
//! backoff, re-subscribes with a raised `since`, pings the relay periodically,
//! and shuts down after a few minutes with nothing to do. Event signatures are
//! not verified here; consumers are expected to do that.
//!
//! All methods that may open a connection must be called from within a Tokio
//! runtime.

mod relay;
mod url;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use nostr::prelude::*;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::relay::{Cmd, QueryMsg};
pub use crate::url::normalize_relay_url;

/// Maximum number of event ids remembered per subscription for deduplication.
const DEDUP_CAPACITY: usize = 50_000;

/// Something that happened in the pool.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum PoolEvent {
    /// An event for a persistent subscription, delivered at most once per
    /// subscription id regardless of how many relays sent it.
    Event {
        relay: String,
        sub_id: String,
        event: Event,
    },
    /// A relay finished sending stored events for a subscription. Sent again
    /// after every (re)subscription on that relay.
    Eose {
        relay: String,
        sub_id: String,
    },
    Connected {
        relay: String,
    },
    Disconnected {
        relay: String,
    },
}

/// Outcome of [`Pool::publish`], keyed by normalized relay URL.
#[derive(Debug, Clone, Default)]
pub struct PublishResult {
    pub accepted: Vec<String>,
    /// Relays that refused the event or did not answer, with the reason.
    pub rejected: Vec<(String, String)>,
}

/// A pool of relay connections. Cheap to clone; all clones share the same
/// connections. Connections are torn down when the last clone is dropped.
#[derive(Clone)]
pub struct Pool {
    inner: Arc<Inner>,
}

struct Inner {
    shared: Arc<Shared>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Dropping the command senders makes every relay task exit.
        self.shared.lock().relays.clear();
    }
}

pub(crate) struct Shared {
    main_keys: Keys,
    events: mpsc::UnboundedSender<PoolEvent>,
    state: Mutex<State>,
}

#[derive(Default)]
pub(crate) struct State {
    relays: HashMap<String, mpsc::UnboundedSender<Cmd>>,
    subs: HashMap<String, PoolSub>,
    auth_keys: HashMap<PublicKey, AuthKey>,
    connected: BTreeSet<String>,
}

struct PoolSub {
    relays: BTreeSet<String>,
    seen: Seen,
}

struct AuthKey {
    keys: Keys,
    relays: HashSet<String>,
}

/// Bounded set of recently seen event ids, evicting the oldest first.
#[derive(Default)]
struct Seen {
    set: HashSet<EventId>,
    order: VecDeque<EventId>,
}

impl Seen {
    fn insert(&mut self, id: EventId) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > DEDUP_CAPACITY
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
        true
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn emit(&self, event: PoolEvent) {
        let _ = self.events.send(event);
    }

    /// Hand an event for a persistent subscription to the consumer, unless it
    /// was already delivered for that subscription.
    pub(crate) fn deliver(&self, relay: &str, sub_id: &str, event: Event) {
        let mut st = self.lock();
        let Some(sub) = st.subs.get_mut(sub_id) else {
            return;
        };
        if sub.seen.insert(event.id) {
            self.emit(PoolEvent::Event {
                relay: relay.to_string(),
                sub_id: sub_id.to_string(),
                event,
            });
        }
    }

    /// The main key plus every registered key whose scope includes `relay`.
    pub(crate) fn keys_for(&self, relay: &str) -> Vec<Keys> {
        let st = self.lock();
        let mut keys = vec![self.main_keys.clone()];
        keys.extend(
            st.auth_keys
                .values()
                .filter(|k| k.relays.contains(relay))
                .map(|k| k.keys.clone()),
        );
        keys
    }

    pub(crate) fn set_connected(&self, relay: &str, connected: bool) {
        {
            let mut st = self.lock();
            if connected {
                st.connected.insert(relay.to_string());
            } else {
                st.connected.remove(relay);
            }
        }
        let relay = relay.to_string();
        self.emit(if connected {
            PoolEvent::Connected { relay }
        } else {
            PoolEvent::Disconnected { relay }
        });
    }

    /// Send a command to a relay task, spawning the task if needed.
    fn send(self: &Arc<Self>, st: &mut State, relay: &str, cmd: Cmd) {
        let cmd = match st.relays.get(relay) {
            Some(tx) => match tx.send(cmd) {
                Ok(()) => return,
                Err(e) => e.0,
            },
            None => cmd,
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let _ = tx.send(cmd);
        st.relays.insert(relay.to_string(), tx);
        tokio::spawn(relay::run(self.clone(), relay.to_string(), rx));
    }

    /// Send a command to a relay task only if one is running.
    fn send_existing(st: &State, relay: &str, cmd: Cmd) {
        if let Some(tx) = st.relays.get(relay) {
            let _ = tx.send(cmd);
        }
    }
}

fn normalize_all(relays: &[String]) -> BTreeSet<String> {
    relays
        .iter()
        .filter_map(|r| {
            let n = normalize_relay_url(r);
            if n.is_none() {
                tracing::warn!(relay = %r, "ignoring invalid relay url");
            }
            n
        })
        .collect()
}

impl Pool {
    pub fn new(main_keys: Keys) -> (Pool, mpsc::UnboundedReceiver<PoolEvent>) {
        let (events, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            main_keys,
            events,
            state: Mutex::new(State::default()),
        });
        let pool = Pool {
            inner: Arc::new(Inner { shared }),
        };
        (pool, rx)
    }

    fn shared(&self) -> &Arc<Shared> {
        &self.inner.shared
    }

    /// Register NIP-42 keys scoped to relays (normalized URLs). Idempotent;
    /// widening scope or adding keys triggers immediate AUTH for those keys on
    /// connected relays that already sent a challenge, then re-sends
    /// subscriptions on those relays that were CLOSED for auth-required.
    pub fn register_auth_keys(&self, relays: &[String], keys: Vec<Keys>) {
        let relays = normalize_all(relays);
        let mut st = self.shared().lock();
        let mut affected = BTreeSet::new();
        for k in keys {
            let entry = st
                .auth_keys
                .entry(k.public_key())
                .or_insert_with(|| AuthKey {
                    keys: k,
                    relays: HashSet::new(),
                });
            for r in &relays {
                if entry.relays.insert(r.clone()) {
                    affected.insert(r.clone());
                }
            }
        }
        for r in &affected {
            Shared::send_existing(&st, r, Cmd::AuthKeysChanged);
        }
    }

    /// Forget keys. Connections that already authenticated as them stay
    /// authenticated; they are just not used for future challenges.
    pub fn unregister_auth_keys(&self, pubkeys: &[PublicKey]) {
        let mut st = self.shared().lock();
        for pk in pubkeys {
            st.auth_keys.remove(pk);
        }
    }

    /// Persistent subscription; replaces one with the same id. Connects to
    /// relays lazily. On reconnect, re-REQ with each filter's `since` raised to
    /// (newest created_at seen on that relay for that sub) - 60s, never lowered
    /// below the original since. Each event id is delivered at most once per
    /// sub_id (bounded to the most recent 50k ids per subscription).
    pub fn subscribe(&self, sub_id: &str, relays: &[String], filters: Vec<Filter>) {
        let relays = normalize_all(relays);
        let shared = self.shared();
        let mut st = shared.lock();
        let old = match st.subs.get_mut(sub_id) {
            Some(sub) => std::mem::replace(&mut sub.relays, relays.clone()),
            None => {
                st.subs.insert(
                    sub_id.to_string(),
                    PoolSub {
                        relays: relays.clone(),
                        seen: Seen::default(),
                    },
                );
                BTreeSet::new()
            }
        };
        for r in old.difference(&relays) {
            Shared::send_existing(
                &st,
                r,
                Cmd::Unsubscribe {
                    sub_id: sub_id.to_string(),
                },
            );
        }
        for r in &relays {
            shared.send(
                &mut st,
                r,
                Cmd::Subscribe {
                    sub_id: sub_id.to_string(),
                    filters: filters.clone(),
                },
            );
        }
    }

    pub fn unsubscribe(&self, sub_id: &str) {
        let mut st = self.shared().lock();
        let Some(sub) = st.subs.remove(sub_id) else {
            return;
        };
        for r in &sub.relays {
            Shared::send_existing(
                &st,
                r,
                Cmd::Unsubscribe {
                    sub_id: sub_id.to_string(),
                },
            );
        }
    }

    /// One-shot query: REQ on each relay, collect until EOSE (or CLOSED) from
    /// all or timeout; dedup by id. A relay that answers `auth-required` is
    /// authenticated against and asked once more. Does not emit PoolEvents.
    pub async fn query(
        &self,
        relays: &[String],
        filters: Vec<Filter>,
        timeout: Duration,
    ) -> Vec<Event> {
        let deadline = Instant::now() + timeout;
        let relays = normalize_all(relays);
        if relays.is_empty() {
            return Vec::new();
        }
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut ids = Vec::with_capacity(relays.len());
        {
            let shared = self.shared();
            let mut st = shared.lock();
            for r in &relays {
                let id = SubscriptionId::generate();
                ids.push((r.clone(), id.clone()));
                shared.send(
                    &mut st,
                    r,
                    Cmd::Query {
                        id,
                        filters: filters.clone(),
                        tx: tx.clone(),
                    },
                );
            }
        }
        drop(tx);

        let mut remaining = relays.len();
        let mut seen = HashSet::new();
        let mut events = Vec::new();
        while remaining > 0 {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(QueryMsg::Event(event))) => {
                    if seen.insert(event.id) {
                        events.push(*event);
                    }
                }
                Ok(Some(QueryMsg::Done)) => remaining -= 1,
                Ok(None) | Err(_) => break,
            }
        }

        let st = self.shared().lock();
        for (r, id) in ids {
            Shared::send_existing(&st, &r, Cmd::CancelQuery { id });
        }
        events
    }

    /// Publish to relays, waiting for OK until timeout. A relay that answers
    /// `auth-required` is authenticated against and sent the event once more.
    pub async fn publish(
        &self,
        relays: &[String],
        event: &Event,
        timeout: Duration,
    ) -> PublishResult {
        let deadline = Instant::now() + timeout;
        let relays = normalize_all(relays);
        let mut pending = Vec::with_capacity(relays.len());
        {
            let shared = self.shared();
            let mut st = shared.lock();
            for r in relays {
                let (tx, rx) = oneshot::channel();
                shared.send(
                    &mut st,
                    &r,
                    Cmd::Publish {
                        event: Box::new(event.clone()),
                        tx,
                    },
                );
                pending.push((r, rx));
            }
        }

        let mut result = PublishResult::default();
        let mut timed_out = Vec::new();
        for (r, rx) in pending {
            match tokio::time::timeout_at(deadline, rx).await {
                Ok(Ok(Ok(()))) => result.accepted.push(r),
                Ok(Ok(Err(reason))) => result.rejected.push((r, reason)),
                Ok(Err(_)) => result.rejected.push((r, "relay task stopped".to_string())),
                Err(_) => {
                    result.rejected.push((r.clone(), "timeout".to_string()));
                    timed_out.push(r);
                }
            }
        }

        let st = self.shared().lock();
        for r in timed_out {
            Shared::send_existing(&st, &r, Cmd::CancelPublish { id: event.id });
        }
        result
    }

    /// Relays currently connected.
    pub fn connected(&self) -> Vec<String> {
        self.shared().lock().connected.iter().cloned().collect()
    }
}
