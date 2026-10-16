//! The client-server API, spoken as the appservice. Every call can act as any
//! user in the bridge's namespace (`?user_id=`), and with encryption, as a
//! specific device (MSC3202 device masquerading).

use std::time::Duration;

use anyhow::{Result, anyhow};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
#[error("{method} {path}: {status} {errcode}: {error}")]
pub struct MatrixError {
    pub method: Method,
    pub path: String,
    pub status: StatusCode,
    pub errcode: String,
    pub error: String,
}

impl MatrixError {
    pub fn is(&self, errcode: &str) -> bool {
        self.errcode == errcode
    }
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
    as_token: String,
}

pub fn enc(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Who a request acts as.
#[derive(Clone, Copy, Debug)]
pub struct As<'a> {
    pub user: Option<&'a str>,
    pub device: Option<&'a str>,
}

impl<'a> As<'a> {
    pub const BOT: As<'static> = As { user: None, device: None };

    pub fn user(user: &'a str) -> Self {
        As { user: Some(user), device: None }
    }
}

impl Client {
    pub fn new(base: &str, as_token: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("armada-matrix-bridge/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client");
        Client { http, base: base.to_owned(), as_token: as_token.to_owned() }
    }

    fn builder(&self, method: Method, path: &str, who: As) -> reqwest::RequestBuilder {
        let mut req = self.http.request(method, format!("{}{}", self.base, path)).bearer_auth(&self.as_token);
        let mut query: Vec<(&str, &str)> = vec![];
        if let Some(user) = who.user {
            query.push(("user_id", user));
        }
        if let Some(device) = who.device {
            query.push(("org.matrix.msc3202.device_id", device));
            query.push(("device_id", device));
        }
        if !query.is_empty() {
            req = req.query(&query);
        }
        req
    }

    /// Send a request, retrying on rate limits and transient failures.
    pub async fn call(&self, method: Method, path: &str, who: As<'_>, body: Option<&Value>) -> Result<Value> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let mut req = self.builder(method.clone(), path, who);
            if let Some(body) = body {
                req = req.json(body);
            }
            let res = match req.send().await {
                Ok(r) => r,
                Err(e) if attempt < 5 => {
                    tracing::warn!(%path, error = %e, "matrix request failed; retrying");
                    tokio::time::sleep(Duration::from_millis(500 * 2u64.pow(attempt))).await;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let status = res.status();
            let bytes = res.bytes().await?;
            let value: Value = if bytes.is_empty() { json!({}) } else { serde_json::from_slice(&bytes).unwrap_or(json!({})) };
            if status.is_success() {
                return Ok(value);
            }
            if (status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()) && attempt < 6 {
                let wait = value.get("retry_after_ms").and_then(Value::as_u64).unwrap_or(1000 * 2u64.pow(attempt));
                tokio::time::sleep(Duration::from_millis(wait.min(30_000))).await;
                continue;
            }
            return Err(MatrixError {
                method,
                path: path.to_owned(),
                status,
                errcode: value.get("errcode").and_then(Value::as_str).unwrap_or("M_UNKNOWN").to_owned(),
                error: value.get("error").and_then(Value::as_str).unwrap_or("").to_owned(),
            }
            .into());
        }
    }

    pub async fn get(&self, path: &str, who: As<'_>) -> Result<Value> {
        self.call(Method::GET, path, who, None).await
    }

    pub async fn post(&self, path: &str, who: As<'_>, body: &Value) -> Result<Value> {
        self.call(Method::POST, path, who, Some(body)).await
    }

    pub async fn put(&self, path: &str, who: As<'_>, body: &Value) -> Result<Value> {
        self.call(Method::PUT, path, who, Some(body)).await
    }

    // ── Users ───────────────────────────────────────────────────────────────

    /// Register a user in the appservice's namespace; already-registered is fine.
    pub async fn register(&self, localpart: &str) -> Result<()> {
        let body = json!({ "type": "m.login.application_service", "username": localpart, "inhibit_login": true });
        match self.post("/_matrix/client/v3/register", As::BOT, &body).await {
            Ok(_) => Ok(()),
            Err(e) if e.downcast_ref::<MatrixError>().is_some_and(|m| m.is("M_USER_IN_USE")) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub async fn set_displayname(&self, user: &str, name: &str) -> Result<()> {
        self.put(&format!("/_matrix/client/v3/profile/{}/displayname", enc(user)), As::user(user), &json!({ "displayname": name })).await?;
        Ok(())
    }

    pub async fn set_avatar(&self, user: &str, mxc: &str) -> Result<()> {
        self.put(&format!("/_matrix/client/v3/profile/{}/avatar_url", enc(user)), As::user(user), &json!({ "avatar_url": mxc })).await?;
        Ok(())
    }

    pub async fn profile(&self, user: &str) -> Result<Value> {
        self.get(&format!("/_matrix/client/v3/profile/{}", enc(user)), As::BOT).await
    }

    // ── Rooms ───────────────────────────────────────────────────────────────

    pub async fn create_room(&self, who: As<'_>, body: &Value) -> Result<String> {
        let res = self.post("/_matrix/client/v3/createRoom", who, body).await?;
        res.get("room_id").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| anyhow!("createRoom returned no room_id"))
    }

    pub async fn join(&self, user: &str, room: &str) -> Result<()> {
        self.post(&format!("/_matrix/client/v3/join/{}", enc(room)), As::user(user), &json!({})).await?;
        Ok(())
    }

    pub async fn invite(&self, who: As<'_>, room: &str, user: &str) -> Result<()> {
        match self.post(&format!("/_matrix/client/v3/rooms/{}/invite", enc(room)), who, &json!({ "user_id": user })).await {
            Ok(_) => Ok(()),
            // Already joined or invited.
            Err(e) if e.downcast_ref::<MatrixError>().is_some_and(|m| m.status == StatusCode::FORBIDDEN && m.error.contains("already")) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub async fn leave(&self, user: &str, room: &str) -> Result<()> {
        self.post(&format!("/_matrix/client/v3/rooms/{}/leave", enc(room)), As::user(user), &json!({})).await?;
        Ok(())
    }

    pub async fn kick(&self, who: As<'_>, room: &str, user: &str, reason: &str) -> Result<()> {
        self.post(&format!("/_matrix/client/v3/rooms/{}/kick", enc(room)), who, &json!({ "user_id": user, "reason": reason })).await?;
        Ok(())
    }



    pub async fn send(&self, who: As<'_>, room: &str, event_type: &str, content: &Value) -> Result<String> {
        let txn = hex::encode(rand::random::<[u8; 16]>());
        let path = format!("/_matrix/client/v3/rooms/{}/send/{}/{}", enc(room), enc(event_type), txn);
        let res = self.put(&path, who, content).await?;
        res.get("event_id").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| anyhow!("send returned no event_id"))
    }

    /// Send with an explicit origin timestamp (appservice timestamp massaging), so
    /// bridged history keeps Armada's order and times.
    pub async fn send_ts(&self, who: As<'_>, room: &str, event_type: &str, content: &Value, ts_ms: u64) -> Result<String> {
        let txn = hex::encode(rand::random::<[u8; 16]>());
        let ts = ts_ms.min(super::super::bridge::now_ms());
        let path = format!("/_matrix/client/v3/rooms/{}/send/{}/{}?ts={ts}", enc(room), enc(event_type), txn);
        let res = self.put(&path, who, content).await?;
        res.get("event_id").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| anyhow!("send returned no event_id"))
    }

    pub async fn redact(&self, who: As<'_>, room: &str, event_id: &str, reason: Option<&str>) -> Result<()> {
        let txn = hex::encode(rand::random::<[u8; 16]>());
        let path = format!("/_matrix/client/v3/rooms/{}/redact/{}/{}", enc(room), enc(event_id), txn);
        let body = reason.map(|r| json!({ "reason": r })).unwrap_or_else(|| json!({}));
        self.put(&path, who, &body).await?;
        Ok(())
    }

    pub async fn set_state(&self, who: As<'_>, room: &str, event_type: &str, state_key: &str, content: &Value) -> Result<String> {
        let path = format!("/_matrix/client/v3/rooms/{}/state/{}/{}", enc(room), enc(event_type), enc(state_key));
        let res = self.put(&path, who, content).await?;
        Ok(res.get("event_id").and_then(Value::as_str).unwrap_or_default().to_owned())
    }

    /// A state event's content, or `None` if absent.
    pub async fn get_state(&self, who: As<'_>, room: &str, event_type: &str, state_key: &str) -> Result<Option<Value>> {
        let path = format!("/_matrix/client/v3/rooms/{}/state/{}/{}", enc(room), enc(event_type), enc(state_key));
        match self.get(&path, who).await {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.downcast_ref::<MatrixError>().is_some_and(|m| m.is("M_NOT_FOUND")) => Ok(None),
            Err(e) => Err(e),
        }
    }


    pub async fn typing(&self, user: &str, room: &str, typing: bool) -> Result<()> {
        let body = if typing { json!({ "typing": true, "timeout": 8000 }) } else { json!({ "typing": false }) };
        self.put(&format!("/_matrix/client/v3/rooms/{}/typing/{}", enc(room), enc(user)), As::user(user), &body).await?;
        Ok(())
    }

    // ── Media ───────────────────────────────────────────────────────────────

    pub async fn upload(&self, who: As<'_>, bytes: Vec<u8>, content_type: &str, filename: Option<&str>) -> Result<String> {
        let mut req = self.builder(Method::POST, "/_matrix/media/v3/upload", who).header("Content-Type", content_type).body(bytes);
        if let Some(name) = filename {
            req = req.query(&[("filename", name)]);
        }
        let res = req.send().await?;
        let status = res.status();
        let value: Value = res.json().await.unwrap_or(json!({}));
        if !status.is_success() {
            return Err(anyhow!("media upload failed: {status} {value}"));
        }
        value.get("content_uri").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| anyhow!("upload returned no content_uri"))
    }

    /// Download an `mxc://` URI through authenticated media, capped at `max_bytes`.
    pub async fn download(&self, mxc: &str, max_bytes: u64) -> Result<(Vec<u8>, Option<String>)> {
        let rest = mxc.strip_prefix("mxc://").ok_or_else(|| anyhow!("not an mxc URI: {mxc}"))?;
        let (server, media) = rest.split_once('/').ok_or_else(|| anyhow!("malformed mxc URI"))?;
        let path = format!("/_matrix/client/v1/media/download/{}/{}", enc(server), enc(media));
        let res = self.builder(Method::GET, &path, As::BOT).send().await?;
        if !res.status().is_success() {
            return Err(anyhow!("media download failed: {}", res.status()));
        }
        if res.content_length().is_some_and(|l| l > max_bytes) {
            return Err(anyhow!("media exceeds {max_bytes} bytes"));
        }
        let content_type = res.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_owned);
        let bytes = read_capped(res, max_bytes).await?;
        Ok((bytes, content_type))
    }

    pub async fn ping(&self, appservice_id: &str) -> Result<()> {
        self.post(&format!("/_matrix/client/v1/appservice/{}/ping", enc(appservice_id)), As::BOT, &json!({})).await?;
        Ok(())
    }

}

/// Read a response body, refusing more than `max` bytes even if Content-Length lied.
pub async fn read_capped(mut res: reqwest::Response, max: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = res.chunk().await? {
        if out.len() as u64 + chunk.len() as u64 > max {
            return Err(anyhow!("body exceeds {max} bytes"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}
