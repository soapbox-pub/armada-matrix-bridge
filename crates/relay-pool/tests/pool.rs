mod mock;

use std::time::Duration;

use mock::MockRelay;
use nostr::prelude::*;
use relay_pool::{Pool, PoolEvent};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::{Instant, timeout};

const WAIT: Duration = Duration::from_secs(10);

fn note(keys: &Keys, kind: u16, content: &str, created_at: u64) -> Event {
    EventBuilder::new(Kind::from(kind), content)
        .custom_created_at(Timestamp::from_secs(created_at))
        .finalize(keys)
        .unwrap()
}

/// Next Event/Eose for `sub_id`, skipping connection events.
async fn next_sub_event(rx: &mut UnboundedReceiver<PoolEvent>, sub_id: &str) -> PoolEvent {
    loop {
        let ev = timeout(WAIT, rx.recv())
            .await
            .expect("timed out")
            .expect("closed");
        match &ev {
            PoolEvent::Event { sub_id: s, .. } | PoolEvent::Eose { sub_id: s, .. }
                if s == sub_id =>
            {
                return ev;
            }
            _ => {}
        }
    }
}

/// Collect events for `sub_id` until `eoses` EOSEs have arrived.
async fn collect_until_eose(
    rx: &mut UnboundedReceiver<PoolEvent>,
    sub_id: &str,
    eoses: usize,
) -> Vec<Event> {
    let mut events = Vec::new();
    let mut seen_eose = 0;
    while seen_eose < eoses {
        match next_sub_event(rx, sub_id).await {
            PoolEvent::Event { event, .. } => events.push(event),
            PoolEvent::Eose { .. } => seen_eose += 1,
            _ => unreachable!(),
        }
    }
    events
}

/// Assert nothing for `sub_id` arrives within `d`.
async fn assert_quiet(rx: &mut UnboundedReceiver<PoolEvent>, sub_id: &str, d: Duration) {
    let deadline = Instant::now() + d;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Err(_) => return,
            Ok(None) => panic!("closed"),
            Ok(Some(PoolEvent::Event {
                sub_id: s, event, ..
            })) if s == sub_id => {
                panic!("unexpected event {}", event.id)
            }
            Ok(Some(PoolEvent::Eose { sub_id: s, .. })) if s == sub_id => panic!("unexpected EOSE"),
            Ok(Some(_)) => {}
        }
    }
}

#[tokio::test]
async fn subscribe_receives_stored_live_and_eose() {
    let relay = MockRelay::start(false).await;
    let author = Keys::generate();
    let stored = note(&author, 1, "stored", 1_700_000_000);
    relay.store(stored.clone());
    relay.store(note(&author, 7, "other kind", 1_700_000_000));

    let (pool, mut rx) = Pool::new(Keys::generate());
    pool.subscribe("s", &relay.urls(), vec![Filter::new().kind(Kind::TextNote)]);

    match next_sub_event(&mut rx, "s").await {
        PoolEvent::Event {
            event, relay: r, ..
        } => {
            assert_eq!(event.id, stored.id);
            assert_eq!(r, relay.url);
        }
        other => panic!("expected event, got {other:?}"),
    }
    assert!(matches!(
        next_sub_event(&mut rx, "s").await,
        PoolEvent::Eose { .. }
    ));
    assert_eq!(pool.connected(), vec![relay.url.clone()]);

    let live = note(&author, 1, "live", 1_700_000_100);
    relay.inject(live.clone());
    match next_sub_event(&mut rx, "s").await {
        PoolEvent::Event { event, .. } => assert_eq!(event.id, live.id),
        other => panic!("expected event, got {other:?}"),
    }

    pool.unsubscribe("s");
    tokio::time::sleep(Duration::from_millis(100)).await;
    relay.inject(note(&author, 1, "after unsubscribe", 1_700_000_200));
    assert_quiet(&mut rx, "s", Duration::from_millis(300)).await;
}

#[tokio::test]
async fn dedups_across_relays() {
    let a = MockRelay::start(false).await;
    let b = MockRelay::start(false).await;
    let author = Keys::generate();
    let shared = note(&author, 1, "both", 1_700_000_000);
    let only_b = note(&author, 1, "only b", 1_700_000_001);
    a.store(shared.clone());
    b.store(shared.clone());
    b.store(only_b.clone());

    let (pool, mut rx) = Pool::new(Keys::generate());
    pool.subscribe(
        "s",
        &[a.url.clone(), b.url.clone()],
        vec![Filter::new().kind(Kind::TextNote)],
    );

    let events = collect_until_eose(&mut rx, "s", 2).await;
    let mut ids: Vec<EventId> = events.iter().map(|e| e.id).collect();
    ids.sort();
    let mut expected = vec![shared.id, only_b.id];
    expected.sort();
    assert_eq!(ids, expected);

    // A live event arriving from both relays is still delivered once.
    let live = note(&author, 1, "live both", 1_700_000_002);
    a.inject(live.clone());
    b.inject(live.clone());
    match next_sub_event(&mut rx, "s").await {
        PoolEvent::Event { event, .. } => assert_eq!(event.id, live.id),
        other => panic!("expected event, got {other:?}"),
    }
    assert_quiet(&mut rx, "s", Duration::from_millis(300)).await;
}

#[tokio::test]
async fn query_returns_at_eose() {
    let a = MockRelay::start(false).await;
    let b = MockRelay::start(false).await;
    let author = Keys::generate();
    let e1 = note(&author, 1, "one", 1_700_000_000);
    let e2 = note(&author, 1, "two", 1_700_000_001);
    a.store(e1.clone());
    a.store(e2.clone());
    b.store(e2.clone());
    a.store(note(&Keys::generate(), 1, "someone else", 1_700_000_002));

    let (pool, mut rx) = Pool::new(Keys::generate());
    let start = Instant::now();
    let events = pool
        .query(
            &[a.url.clone(), b.url.clone()],
            vec![Filter::new().author(author.public_key())],
            Duration::from_secs(10),
        )
        .await;
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "query waited for timeout"
    );
    let mut ids: Vec<EventId> = events.iter().map(|e| e.id).collect();
    ids.sort();
    let mut expected = vec![e1.id, e2.id];
    expected.sort();
    assert_eq!(ids, expected);

    // Queries emit no subscription events.
    while let Ok(ev) = rx.try_recv() {
        assert!(
            matches!(ev, PoolEvent::Connected { .. }),
            "unexpected {ev:?}"
        );
    }
}

#[tokio::test]
async fn query_times_out_on_unreachable_relay() {
    let (pool, _rx) = Pool::new(Keys::generate());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = format!("ws://{}", listener.local_addr().unwrap());
    drop(listener);
    let start = Instant::now();
    let events = pool
        .query(&[dead], vec![Filter::new()], Duration::from_secs(5))
        .await;
    assert!(events.is_empty());
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "connection failure should end the query"
    );
}

#[tokio::test]
async fn publish_accepted_and_rejected() {
    let relay = MockRelay::start(false).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = format!("ws://{}", listener.local_addr().unwrap());
    drop(listener);

    let keys = Keys::generate();
    let (pool, _rx) = Pool::new(keys.clone());

    let good = note(&keys, 1, "hello", 1_700_000_000);
    let res = pool
        .publish(
            &[relay.url.clone(), dead.clone()],
            &good,
            Duration::from_secs(5),
        )
        .await;
    assert_eq!(res.accepted, vec![relay.url.clone()]);
    assert_eq!(res.rejected.len(), 1);
    assert_eq!(res.rejected[0].0, dead);

    let bad = note(&keys, 1, "reject", 1_700_000_000);
    let res = pool
        .publish(&relay.urls(), &bad, Duration::from_secs(5))
        .await;
    assert!(res.accepted.is_empty());
    assert_eq!(
        res.rejected,
        vec![(relay.url.clone(), "blocked: nope".to_string())]
    );
}

#[tokio::test]
async fn nip42_authenticates_every_stream_key() {
    let relay = MockRelay::start(true).await;
    let main = Keys::generate();
    let s1 = Keys::generate();
    let s2 = Keys::generate();
    let unrelated = Keys::generate();
    let w1 = note(&s1, 1059, "wrap 1", 1_700_000_000);
    let w2 = note(&s2, 1059, "wrap 2", 1_700_000_001);
    relay.store(w1.clone());
    relay.store(w2.clone());

    let (pool, mut rx) = Pool::new(main.clone());
    pool.register_auth_keys(&relay.urls(), vec![s1.clone(), s2.clone()]);
    // Scoped to another relay; must not be sent here.
    pool.register_auth_keys(
        &["wss://elsewhere.example".to_string()],
        vec![unrelated.clone()],
    );

    let filter = Filter::new()
        .kind(Kind::GiftWrap)
        .authors([s1.public_key(), s2.public_key()]);
    pool.subscribe("concord", &relay.urls(), vec![filter.clone()]);

    let events = collect_until_eose(&mut rx, "concord", 1).await;
    let mut ids: Vec<EventId> = events.iter().map(|e| e.id).collect();
    ids.sort();
    let mut expected = vec![w1.id, w2.id];
    expected.sort();
    assert_eq!(ids, expected);

    let authed = relay.authed();
    for pk in [main.public_key(), s1.public_key(), s2.public_key()] {
        assert!(authed.contains(&pk), "{pk} did not authenticate");
    }
    assert!(!authed.contains(&unrelated.public_key()));
    assert_eq!(authed.len(), 3, "keys authenticated more than once");

    // The first REQ was refused, the retry after AUTH succeeded.
    assert!(relay.reqs_for("concord").len() >= 2);

    // Query and publish on the already-authenticated connection.
    let got = pool
        .query(&relay.urls(), vec![filter], Duration::from_secs(5))
        .await;
    assert_eq!(got.len(), 2);
    let w3 = note(&s1, 1059, "wrap 3", 1_700_000_002);
    let res = pool
        .publish(&relay.urls(), &w3, Duration::from_secs(5))
        .await;
    assert_eq!(res.accepted, vec![relay.url.clone()]);
}

#[tokio::test]
async fn nip42_query_and_publish_on_fresh_connection() {
    let relay = MockRelay::start(true).await;
    let main = Keys::generate();
    let s1 = Keys::generate();
    relay.store(note(&s1, 1059, "wrap", 1_700_000_000));

    let (pool, _rx) = Pool::new(main);
    pool.register_auth_keys(&relay.urls(), vec![s1.clone()]);

    let got = pool
        .query(
            &relay.urls(),
            vec![Filter::new().author(s1.public_key())],
            Duration::from_secs(5),
        )
        .await;
    assert_eq!(got.len(), 1);

    // A key the relay never saw AUTH for: publish is refused after one retry.
    let stranger = Keys::generate();
    let ev = note(&stranger, 1059, "nope", 1_700_000_000);
    let res = pool
        .publish(&relay.urls(), &ev, Duration::from_secs(5))
        .await;
    assert!(res.accepted.is_empty());
    assert!(
        res.rejected[0].1.contains("auth-required"),
        "{:?}",
        res.rejected
    );

    // Query for an unauthenticated author ends without waiting for the timeout.
    let start = Instant::now();
    let got = pool
        .query(
            &relay.urls(),
            vec![Filter::new().author(stranger.public_key())],
            Duration::from_secs(5),
        )
        .await;
    assert!(got.is_empty());
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn late_key_registration_triggers_auth_and_resubscribe() {
    let relay = MockRelay::start(true).await;
    let main = Keys::generate();
    let s1 = Keys::generate();
    let s2 = Keys::generate();
    let w1 = note(&s1, 1059, "wrap 1", 1_700_000_000);
    let w2 = note(&s2, 1059, "wrap 2", 1_700_000_001);
    relay.store(w1.clone());
    relay.store(w2.clone());

    let (pool, mut rx) = Pool::new(main);
    pool.register_auth_keys(&relay.urls(), vec![s1.clone()]);
    pool.subscribe(
        "concord",
        &relay.urls(),
        vec![Filter::new().authors([s1.public_key(), s2.public_key()])],
    );

    // s2 is not authenticated, so the relay keeps refusing.
    assert_quiet(&mut rx, "concord", Duration::from_millis(800)).await;
    assert!(!relay.authed().contains(&s2.public_key()));

    pool.register_auth_keys(&relay.urls(), vec![s2.clone()]);
    let events = collect_until_eose(&mut rx, "concord", 1).await;
    assert_eq!(events.len(), 2);
    assert!(relay.authed().contains(&s2.public_key()));
    assert_eq!(
        relay.connections(),
        1,
        "should reuse the existing connection"
    );

    // Registering again is a no-op.
    let before = relay.authed().len();
    pool.register_auth_keys(&relay.urls(), vec![s2.clone()]);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(relay.authed().len(), before);
}

#[tokio::test]
async fn reconnect_resubscribes_with_since() {
    let relay = MockRelay::start(false).await;
    let author = Keys::generate();
    let newest = 1_700_000_000;
    let e1 = note(&author, 1, "old", newest - 500);
    let e2 = note(&author, 1, "newest", newest);
    relay.store(e1.clone());
    relay.store(e2.clone());

    let (pool, mut rx) = Pool::new(Keys::generate());
    let original_since = Timestamp::from_secs(1_600_000_000);
    pool.subscribe(
        "s",
        &relay.urls(),
        vec![
            Filter::new().kind(Kind::TextNote).since(original_since),
            Filter::new()
                .kind(Kind::TextNote)
                .since(Timestamp::from_secs(1_800_000_000)),
            Filter::new().kind(Kind::Reaction),
        ],
    );
    let events = collect_until_eose(&mut rx, "s", 1).await;
    assert_eq!(events.len(), 2);

    relay.drop_connections();
    loop {
        let ev = timeout(WAIT, rx.recv()).await.unwrap().unwrap();
        if matches!(ev, PoolEvent::Disconnected { .. }) {
            break;
        }
    }
    loop {
        let ev = timeout(WAIT, rx.recv()).await.unwrap().unwrap();
        if matches!(ev, PoolEvent::Connected { .. }) {
            break;
        }
    }
    // The relay resends e2 (inside the overlap window), but it was already delivered.
    let events = collect_until_eose(&mut rx, "s", 1).await;
    assert!(events.is_empty(), "redelivered {events:?}");

    let reqs = relay.reqs_for("s");
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0][0].since, Some(original_since));
    let raised = Timestamp::from_secs(newest - 60);
    assert_eq!(reqs[1][0].since, Some(raised));
    // Never lowered below the original.
    assert_eq!(reqs[1][1].since, Some(Timestamp::from_secs(1_800_000_000)));
    // Filters without since get one.
    assert_eq!(reqs[1][2].since, Some(raised));

    // Live events still flow after reconnect.
    let live = note(&author, 1, "live", newest + 10);
    relay.inject(live.clone());
    match next_sub_event(&mut rx, "s").await {
        PoolEvent::Event { event, .. } => assert_eq!(event.id, live.id),
        other => panic!("expected event, got {other:?}"),
    }
}
