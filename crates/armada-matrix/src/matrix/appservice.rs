//! The appservice API: the homeserver pushes transactions of room events,
//! ephemeral events (typing), and — with encryption — to-device events and
//! one-time-key counts.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Json;
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// One transaction, split by what the bridge does with each part.
#[derive(Debug, Default)]
pub struct Transaction {
    pub id: String,
    pub events: Vec<Value>,
    pub ephemeral: Vec<Value>,
    pub to_device: Vec<Value>,
    /// MSC3202: `{ user_id: { device_id: { algorithm: count } } }`.
    pub otk_counts: Value,
    pub fallback_keys: Value,
    /// MSC3202: `{ changed: [...], left: [...] }`.
    pub device_lists: Value,
}

#[derive(Clone)]
struct AppState {
    hs_token: Arc<str>,
    tx: mpsc::Sender<Transaction>,
    seen: Arc<tokio::sync::Mutex<lru::LruCache<String, ()>>>,
    namespace: Arc<dyn Fn(&str) -> bool + Send + Sync>,
}

fn authorized(state: &AppState, headers: &HeaderMap, query: &std::collections::HashMap<String, String>) -> bool {
    let header = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    let token = header.or(query.get("access_token").map(String::as_str));
    token.is_some_and(|t| constant_time_eq(t.as_bytes(), state.hs_token.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, Json(json!({ "errcode": "M_FORBIDDEN", "error": "bad hs_token" }))).into_response()
}

fn array(body: &Value, keys: &[&str]) -> Vec<Value> {
    keys.iter().find_map(|k| body.get(*k).and_then(Value::as_array).cloned()).unwrap_or_default()
}

fn object(body: &Value, keys: &[&str]) -> Value {
    keys.iter().find_map(|k| body.get(*k).filter(|v| v.is_object()).cloned()).unwrap_or_else(|| json!({}))
}

async fn transaction(
    State(state): State<AppState>,
    Path(txn_id): Path<String>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&state, &headers, &query) {
        return forbidden();
    }
    if state.seen.lock().await.put(txn_id.clone(), ()).is_some() {
        return Json(json!({})).into_response();
    }
    let txn = Transaction {
        id: txn_id,
        events: array(&body, &["events"]),
        ephemeral: array(&body, &["ephemeral", "de.sorunome.msc2409.ephemeral"]),
        to_device: array(&body, &["to_device", "de.sorunome.msc2409.to_device"]),
        otk_counts: object(&body, &["device_one_time_keys_count", "org.matrix.msc3202.device_one_time_keys_count"]),
        fallback_keys: object(&body, &["device_unused_fallback_key_types", "org.matrix.msc3202.device_unused_fallback_key_types"]),
        device_lists: object(&body, &["device_lists", "org.matrix.msc3202.device_lists"]),
    };
    // Back-pressure: a full queue holds the homeserver, which retries.
    if state.tx.send(txn).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "errcode": "M_UNKNOWN", "error": "shutting down" }))).into_response();
    }
    Json(json!({})).into_response()
}

async fn user_query(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&state, &headers, &query) {
        return forbidden();
    }
    // Ghosts are registered on first use; answering 200 lets clients invite them.
    if (state.namespace)(&user_id) {
        Json(json!({})).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({ "errcode": "M_NOT_FOUND" }))).into_response()
    }
}

async fn not_found(Query(query): Query<std::collections::HashMap<String, String>>, State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers, &query) {
        return forbidden();
    }
    (StatusCode::NOT_FOUND, Json(json!({ "errcode": "M_NOT_FOUND" }))).into_response()
}

async fn ping(Query(query): Query<std::collections::HashMap<String, String>>, State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers, &query) {
        return forbidden();
    }
    Json(json!({})).into_response()
}

pub fn router(hs_token: &str, tx: mpsc::Sender<Transaction>, namespace: impl Fn(&str) -> bool + Send + Sync + 'static) -> Router {
    let state = AppState {
        hs_token: hs_token.into(),
        tx,
        seen: Arc::new(tokio::sync::Mutex::new(lru::LruCache::new(std::num::NonZeroUsize::new(4096).unwrap()))),
        namespace: Arc::new(namespace),
    };
    Router::new()
        .route("/_matrix/app/v1/transactions/{txn}", put(transaction))
        .route("/transactions/{txn}", put(transaction))
        .route("/_matrix/app/v1/users/{user}", get(user_query))
        .route("/users/{user}", get(user_query))
        .route("/_matrix/app/v1/rooms/{alias}", get(not_found))
        .route("/rooms/{alias}", get(not_found))
        .route("/_matrix/app/v1/ping", post(ping))
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024))
}
