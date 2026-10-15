//! End-to-end encryption for bridge-owned users. Each user that speaks in an
//! encrypted room (the bot, and every ghost) gets its own device and Olm machine,
//! so recipients see messages encrypted by the sender's own, cross-signed device
//! rather than by a shared bridge device.
//!
//! Appservices have no /sync: devices are created through MSC4190, requests act
//! as a device through MSC3202 masquerading, and to-device events, one-time-key
//! counts and device-list changes arrive in transactions (MSC2409/MSC3202).

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use matrix_sdk_crypto::types::requests::{AnyIncomingResponse, AnyOutgoingRequest, ToDeviceRequest};
use matrix_sdk_crypto::{DecryptionSettings, EncryptionSettings, EncryptionSyncChanges, OlmMachine, OlmMachineBuilder, TrustRequirement};
use matrix_sdk_sqlite::SqliteCryptoStore;
use reqwest::Method;
use ruma::api::{IncomingResponse, IncomingResponseExt};
use ruma::api::client::sync::sync_events::DeviceLists;
use ruma::serde::Raw;
use ruma::{OneTimeKeyAlgorithm, OwnedUserId, RoomId, TransactionId, UInt, UserId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use super::appservice::Transaction;
use super::client::{As, Client, enc};

type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// `mark_request_as_sent` behind an explicit `Send` boundary: its generic
/// response lifetime otherwise defeats `Send` inference in callers.
fn mark<'a>(machine: &'a OlmMachine, id: &'a TransactionId, response: AnyIncomingResponse<'a>) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        machine.mark_request_as_sent(id, response).await?;
        Ok(())
    })
}

/// A function item (unlike a closure) is higher-ranked over its lifetime.
fn as_user(u: &OwnedUserId) -> &UserId {
    u
}

fn track<'a>(machine: &'a OlmMachine, users: &'a [OwnedUserId]) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        machine.update_tracked_users(users.iter().map(as_user)).await?;
        Ok(())
    })
}

fn missing_sessions<'a>(machine: &'a OlmMachine, users: &'a [OwnedUserId]) -> BoxFuture<'a, Result<Option<(ruma::OwnedTransactionId, ruma::api::client::keys::claim_keys::v3::Request)>>> {
    Box::pin(async move { Ok(machine.get_missing_sessions(users.iter().map(as_user)).await?) })
}

fn share<'a>(machine: &'a OlmMachine, room: &'a RoomId, users: &'a [OwnedUserId], settings: EncryptionSettings) -> BoxFuture<'a, Result<Vec<Arc<ToDeviceRequest>>>> {
    Box::pin(async move { Ok(machine.share_room_key(room, users.iter().map(as_user), settings).await?) })
}

pub struct UserCrypto {
    pub mxid: String,
    pub device: String,
    pub machine: OlmMachine,
    /// One operation at a time per device: Olm state is not reentrant here.
    lock: Mutex<()>,
}

pub struct Crypto {
    mx: Client,
    dir: PathBuf,
    passphrase: String,
    machines: Mutex<HashMap<String, Arc<UserCrypto>>>,
    /// Room → members (joined and invited), invalidated on membership changes.
    members: Mutex<HashMap<String, Vec<OwnedUserId>>>,
}

fn http_ok(body: &[u8]) -> http::Response<&[u8]> {
    http::Response::builder().status(200).body(body).expect("static response")
}

fn parse<R: IncomingResponse>(value: &Value) -> Result<R> {
    let bytes = serde_json::to_vec(value)?;
    R::try_from_http_response(http_ok(&bytes)).map_err(|e| anyhow!("unexpected response shape: {e}"))
}

impl Crypto {
    pub fn new(mx: Client, dir: PathBuf, passphrase: String) -> Self {
        Crypto { mx, dir, passphrase, machines: Mutex::default(), members: Mutex::default() }
    }

    /// A stable device id per user, so a restart reuses the same device.
    fn device_id(mxid: &str) -> String {
        let h = hex::encode(Sha256::digest(mxid.as_bytes()));
        format!("ARMADA{}", h[..10].to_uppercase())
    }

    /// The user's Olm machine, creating its device and keys on first use.
    pub fn machine<'a>(&'a self, mxid: &'a str) -> BoxFuture<'a, Result<Arc<UserCrypto>>> {
        Box::pin(self.machine_inner(mxid))
    }

    async fn machine_inner(&self, mxid: &str) -> Result<Arc<UserCrypto>> {
        let mut machines = self.machines.lock().await;
        if let Some(m) = machines.get(mxid) {
            return Ok(m.clone());
        }
        let device = Self::device_id(mxid);
        // MSC4190: an appservice creates its users' devices directly.
        self.mx
            .put(&format!("/_matrix/client/v3/devices/{}", enc(&device)), As::user(mxid), &json!({ "display_name": "Armada bridge" }))
            .await
            .context("creating the device (is MSC4190 enabled on the homeserver?)")?;
        let user_id = UserId::parse(mxid)?;
        let path = self.dir.join(hex::encode(&Sha256::digest(mxid.as_bytes())[..12]));
        let store = SqliteCryptoStore::open(&path, Some(&self.passphrase)).await.context("opening the crypto store")?;
        let machine = OlmMachineBuilder::new(&user_id, device.as_str().into()).with_crypto_store(store).build().await.context("building the Olm machine")?;
        let uc = Arc::new(UserCrypto { mxid: mxid.to_owned(), device, machine, lock: Mutex::new(()) });
        machines.insert(mxid.to_owned(), uc.clone());
        drop(machines);

        {
            let _guard = uc.lock.lock().await;
            self.flush(&uc).await?;
            if !Box::pin(uc.machine.cross_signing_status()).await.is_complete()
                && let Err(e) = self.bootstrap_cross_signing(&uc).await
            {
                tracing::warn!(%mxid, error = %format!("{e:#}"), "cross-signing bootstrap failed; the device stays unverified");
            }
        }
        Ok(uc)
    }

    fn bootstrap_cross_signing<'a>(&'a self, uc: &'a UserCrypto) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.bootstrap_inner(uc))
    }

    async fn bootstrap_inner(&self, uc: &UserCrypto) -> Result<()> {
        let reqs = Box::pin(uc.machine.bootstrap_cross_signing(false)).await?;
        let who = As { user: Some(&uc.mxid), device: Some(&uc.device) };
        if let Some(upload) = reqs.upload_keys_req {
            self.send_request(uc, upload.request_id(), upload.request()).await?;
        }
        let keys = &reqs.upload_signing_keys_req;
        // MSC3967 / MSC4190: a first upload needs no interactive auth.
        self.mx
            .post(
                "/_matrix/client/v3/keys/device_signing/upload",
                who,
                &json!({ "master_key": keys.master_key, "self_signing_key": keys.self_signing_key, "user_signing_key": keys.user_signing_key }),
            )
            .await?;
        self.mx.post("/_matrix/client/v3/keys/signatures/upload", who, &serde_json::to_value(&reqs.upload_signatures_req.signed_keys)?).await?;
        Ok(())
    }

    /// Send one outgoing request as the user's device and feed the response back.
    fn send_request<'a>(&'a self, uc: &'a UserCrypto, id: &'a TransactionId, request: &'a AnyOutgoingRequest) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.send_request_inner(uc, id, request))
    }

    async fn send_request_inner(&self, uc: &UserCrypto, id: &TransactionId, request: &AnyOutgoingRequest) -> Result<()> {
        let who = As { user: Some(&uc.mxid), device: Some(&uc.device) };
        match request {
            AnyOutgoingRequest::KeysUpload(r) => {
                let mut body = json!({ "one_time_keys": r.one_time_keys, "fallback_keys": r.fallback_keys });
                if let Some(keys) = &r.device_keys {
                    body["device_keys"] = serde_json::to_value(keys)?;
                }
                let res = self.mx.post("/_matrix/client/v3/keys/upload", who, &body).await?;
                mark(&uc.machine, id, (&parse::<ruma::api::client::keys::upload_keys::v3::Response>(&res)?).into()).await?;
            }
            AnyOutgoingRequest::KeysQuery(r) => {
                let mut body = json!({ "device_keys": r.device_keys });
                if let Some(t) = r.timeout {
                    body["timeout"] = json!(t.as_millis() as u64);
                }
                let res = self.mx.post("/_matrix/client/v3/keys/query", who, &body).await?;
                mark(&uc.machine, id, (&parse::<ruma::api::client::keys::get_keys::v3::Response>(&res)?).into()).await?;
            }
            AnyOutgoingRequest::KeysClaim(r) => {
                let mut body = json!({ "one_time_keys": r.one_time_keys });
                if let Some(t) = r.timeout {
                    body["timeout"] = json!(t.as_millis() as u64);
                }
                let res = self.mx.post("/_matrix/client/v3/keys/claim", who, &body).await?;
                mark(&uc.machine, id, (&parse::<ruma::api::client::keys::claim_keys::v3::Response>(&res)?).into()).await?;
            }
            AnyOutgoingRequest::ToDeviceRequest(r) => {
                self.send_to_device(uc, r).await?;
                mark(&uc.machine, id, (&parse::<ruma::api::client::to_device::send_event_to_device::v3::Response>(&json!({}))?).into()).await?;
            }
            AnyOutgoingRequest::SignatureUpload(r) => {
                let res = self.mx.post("/_matrix/client/v3/keys/signatures/upload", who, &serde_json::to_value(&r.signed_keys)?).await?;
                mark(&uc.machine, id, (&parse::<ruma::api::client::keys::upload_signatures::v3::Response>(&res)?).into()).await?;
            }
            // In-room verification is not offered by the bridge.
            AnyOutgoingRequest::RoomMessage(_) => {}
        }
        Ok(())
    }

    async fn send_to_device(&self, uc: &UserCrypto, r: &ToDeviceRequest) -> Result<()> {
        let who = As { user: Some(&uc.mxid), device: Some(&uc.device) };
        let path = format!("/_matrix/client/v3/sendToDevice/{}/{}", enc(&r.event_type.to_string()), enc(r.txn_id.as_str()));
        self.mx.call(Method::PUT, &path, who, Some(&json!({ "messages": r.messages }))).await?;
        Ok(())
    }

    /// Send everything the machine has queued. Caller holds `uc.lock`.
    fn flush<'a>(&'a self, uc: &'a UserCrypto) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.flush_inner(uc))
    }

    async fn flush_inner(&self, uc: &UserCrypto) -> Result<()> {
        for _ in 0..8 {
            let requests = Box::pin(uc.machine.outgoing_requests()).await?;
            if requests.is_empty() {
                break;
            }
            for r in requests {
                if let Err(e) = self.send_request(uc, r.request_id(), r.request()).await {
                    tracing::warn!(mxid = %uc.mxid, error = %format!("{e:#}"), "crypto request failed");
                }
            }
        }
        Ok(())
    }

    /// Feed a transaction's crypto parts to the machines they address.
    pub async fn receive(&self, txn: &Transaction) {
        let changed: Vec<OwnedUserId> = txn.device_lists["changed"].as_array().into_iter().flatten().filter_map(|u| u.as_str()).filter_map(|u| UserId::parse(u).ok()).collect();
        let left: Vec<OwnedUserId> = txn.device_lists["left"].as_array().into_iter().flatten().filter_map(|u| u.as_str()).filter_map(|u| UserId::parse(u).ok()).collect();
        let mut lists = DeviceLists::default();
        lists.changed = changed;
        lists.left = left;

        let mut to_device: HashMap<String, Vec<Raw<ruma::events::AnyToDeviceEvent>>> = HashMap::new();
        for ev in &txn.to_device {
            let Some(user) = ev["to_user_id"].as_str() else { continue };
            if let Ok(raw) = serde_json::from_value(ev.clone()) {
                to_device.entry(user.to_owned()).or_default().push(raw);
            }
        }
        let mut users: Vec<String> = to_device.keys().cloned().collect();
        if let Some(o) = txn.otk_counts.as_object() {
            users.extend(o.keys().cloned());
        }
        // Device-list changes matter to every loaded machine.
        if !lists.changed.is_empty() || !lists.left.is_empty() {
            users.extend(self.machines.lock().await.keys().cloned());
        }
        users.sort();
        users.dedup();
        for user in users {
            let loaded = self.machines.lock().await.get(&user).cloned();
            let Some(uc) = loaded else { continue };
            let counts: BTreeMap<OneTimeKeyAlgorithm, UInt> = txn.otk_counts[&user][&uc.device]
                .as_object()
                .map(|o| o.iter().filter_map(|(k, v)| Some((OneTimeKeyAlgorithm::from(k.as_str()), UInt::new(v.as_u64()?)?))).collect())
                .unwrap_or_default();
            let fallback: Option<Vec<OneTimeKeyAlgorithm>> =
                txn.fallback_keys[&user][&uc.device].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).map(OneTimeKeyAlgorithm::from).collect());
            let _guard = uc.lock.lock().await;
            let changes = EncryptionSyncChanges {
                to_device_events: to_device.remove(&user).unwrap_or_default(),
                changed_devices: &lists,
                one_time_keys_counts: &counts,
                unused_fallback_keys: fallback.as_deref(),
                next_batch_token: None,
            };
            let settings = DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };
            if let Err(e) = Box::pin(uc.machine.receive_sync_changes(changes, &settings)).await {
                tracing::warn!(%user, error = %e, "failed to process to-device events");
            }
            let _ = self.flush(&uc).await;
        }
    }

    pub async fn invalidate_members(&self, room: &str) {
        self.members.lock().await.remove(room);
    }

    async fn room_members(&self, room: &str) -> Result<Vec<OwnedUserId>> {
        if let Some(m) = self.members.lock().await.get(room) {
            return Ok(m.clone());
        }
        let res = self.mx.get(&format!("/_matrix/client/v3/rooms/{}/members?not_membership=leave", enc(room)), As::BOT).await?;
        let members: Vec<OwnedUserId> = res["chunk"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| matches!(e["content"]["membership"].as_str(), Some("join" | "invite")))
            .filter_map(|e| e["state_key"].as_str())
            .filter_map(|u| UserId::parse(u).ok())
            .collect();
        self.members.lock().await.insert(room.to_owned(), members.clone());
        Ok(members)
    }

    /// Encrypt `content` as `sender` for everyone in the room. Returns the
    /// `m.room.encrypted` content; `m.relates_to` stays in the clear so clients
    /// can thread and aggregate without decrypting.
    pub fn encrypt<'a>(&'a self, sender: &'a str, room: &'a str, event_type: &'a str, content: &'a Value) -> BoxFuture<'a, Result<Value>> {
        Box::pin(self.encrypt_inner(sender, room, event_type, content))
    }

    async fn encrypt_inner(&self, sender: &str, room: &str, event_type: &str, content: &Value) -> Result<Value> {
        let uc = self.machine(sender).await?;
        let members = self.room_members(room).await?;
        let room_id = RoomId::parse(room)?;
        let _guard = uc.lock.lock().await;
        track(&uc.machine, &members).await?;
        self.flush(&uc).await?;
        if let Some((id, claim)) = missing_sessions(&uc.machine, &members).await? {
            let request = AnyOutgoingRequest::KeysClaim(claim);
            self.send_request(&uc, &id, &request).await?;
        }
        let settings = EncryptionSettings { rotation_period: Duration::from_secs(7 * 24 * 3600), ..Default::default() };
        for request in share(&uc.machine, &room_id, &members, settings).await? {
            self.send_to_device(&uc, &request).await?;
            mark(&uc.machine, &request.txn_id, (&parse::<ruma::api::client::to_device::send_event_to_device::v3::Response>(&json!({}))?).into()).await?;
        }
        let raw: Raw<ruma::events::AnyMessageLikeEventContent> = Raw::new(content)?.cast_unchecked();
        let result = Box::pin(uc.machine.encrypt_room_event_raw(&room_id, event_type, &raw)).await?;
        let mut encrypted: Value = serde_json::from_str(result.content.json().get())?;
        if let Some(rel) = content.get("m.relates_to") {
            encrypted["m.relates_to"] = rel.clone();
        }
        Ok(encrypted)
    }

    /// Decrypt a room event with the bot's machine (the bot is in every portal).
    pub async fn decrypt(&self, bot: &str, event: &Value) -> Result<Value> {
        let uc = self.machine(bot).await?;
        let room_id = RoomId::parse(event["room_id"].as_str().unwrap_or_default())?;
        let raw = serde_json::from_value(event.clone())?;
        let settings = DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };
        let decrypted = Box::pin(uc.machine.decrypt_room_event(&raw, &room_id, &settings)).await?;
        let inner: Value = serde_json::from_str(decrypted.event.json().get())?;
        let mut out = event.clone();
        out["type"] = inner["type"].clone();
        out["content"] = inner["content"].clone();
        // Relations live in the clear part.
        if let Some(rel) = event["content"].get("m.relates_to") {
            out["content"]["m.relates_to"] = rel.clone();
        }
        Ok(out)
    }
}
