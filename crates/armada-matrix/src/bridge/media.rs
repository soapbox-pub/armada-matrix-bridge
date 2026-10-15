//! Media in both directions: Blossom blobs (client-encrypted, as Armada sends
//! them) and the Matrix media repository.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use concord::media::{self, Imeta};
use nostr::prelude::{Keys, Kind, Tag, Timestamp, UnsignedEvent};

use super::Bridge;
use crate::matrix::As;
use crate::matrix::client::read_capped;

/// Refuse URLs that would make the bridge fetch from its own network.
fn check_url(raw: &str) -> Result<url::Url> {
    let url = url::Url::parse(raw)?;
    if !matches!(url.scheme(), "https" | "http") {
        bail!("unsupported URL scheme");
    }
    let host = url.host_str().ok_or_else(|| anyhow!("URL has no host"))?;
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".lan") || host.ends_with(".local") || host.ends_with(".internal") {
        bail!("refusing a local host");
    }
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        let private = match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast(),
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
        };
        if private {
            bail!("refusing a private address");
        }
    }
    Ok(url)
}

/// Fetch a URL, capped at `max` bytes.
pub async fn fetch(b: &Bridge, raw: &str, max: u64) -> Result<(Vec<u8>, Option<String>)> {
    let url = check_url(raw)?;
    let res = b.http.get(url).send().await?;
    if !res.status().is_success() {
        bail!("fetch failed: {}", res.status());
    }
    if res.content_length().is_some_and(|l| l > max) {
        bail!("file exceeds {max} bytes");
    }
    let mime = res.headers().get("content-type").and_then(|v| v.to_str().ok()).map(|s| s.split(';').next().unwrap_or(s).trim().to_owned());
    Ok((read_capped(res, max).await?, mime))
}

/// Copy a public image (an avatar) into the Matrix media repository.
pub async fn rehost_url(b: &Bridge, url: &str) -> Result<String> {
    let (bytes, mime) = fetch(b, url, 5 * 1024 * 1024).await?;
    let mime = mime.filter(|m| m.starts_with("image/")).ok_or_else(|| anyhow!("not an image"))?;
    b.mx.upload(As::BOT, bytes, &mime, None).await
}

/// A downloaded Armada attachment, decrypted.
pub struct Attachment {
    pub bytes: Vec<u8>,
    pub mime: String,
    pub name: String,
    pub dim: Option<(u32, u32)>,
    pub duration: Option<f64>,
    pub alt: Option<String>,
}

/// Download (and decrypt, if client-encrypted) an `imeta` attachment, checking
/// the stored hash so a swapped blob fails closed.
pub async fn download_imeta(b: &Bridge, imeta: &Imeta) -> Result<Attachment> {
    let (blob, served_mime) = fetch(b, &imeta.url, b.config.bridge.max_media_bytes).await?;
    if let Some(x) = &imeta.x
        && !x.eq_ignore_ascii_case(&media::sha256_hex(&blob))
    {
        bail!("blob hash does not match its imeta");
    }
    let bytes = match &imeta.encryption {
        Some(key) => media::decrypt(&blob, key).ok_or_else(|| anyhow!("attachment failed to decrypt"))?,
        None => blob,
    };
    if let Some(ox) = &imeta.ox
        && imeta.encryption.is_some()
        && !ox.eq_ignore_ascii_case(&media::sha256_hex(&bytes))
    {
        bail!("decrypted attachment does not match its hash");
    }
    let mime = imeta.mime.clone().or(served_mime.filter(|_| imeta.encryption.is_none())).unwrap_or_else(|| "application/octet-stream".into());
    // Blossom URLs are hashes; name the file from its type instead.
    let (kind, ext) = mime.split_once('/').unwrap_or(("file", "bin"));
    let ext = ext.split(['+', ';']).next().unwrap_or("bin").replace("jpeg", "jpg");
    let name = format!("{}.{ext}", if kind == "application" { "file" } else { kind });
    Ok(Attachment { bytes, mime, name, dim: imeta.dim, duration: imeta.duration, alt: imeta.alt.clone() })
}

/// The BUD-01/02 upload authorization: a kind-24242 event, base64 in the header.
fn blossom_auth(keys: &Keys, sha256: &str) -> Result<String> {
    let expiration = Timestamp::now().as_secs() + 300;
    let tags = [
        Tag::parse(["t", "upload"])?,
        Tag::parse(["x", sha256])?,
        Tag::parse(["expiration".to_string(), expiration.to_string()])?,
    ];
    let event = nostr::event::FinalizeEvent::finalize(UnsignedEvent::new(keys.public_key(), Timestamp::now(), Kind::Custom(24242), tags, "Upload"), keys)?;
    Ok(format!("Nostr {}", STANDARD.encode(event.as_json())))
}

/// Upload a blob to the first Blossom server that takes it, authorized by
/// `keys`. Returns its URL.
pub async fn upload_blob(b: &Bridge, keys: &Keys, blob: Vec<u8>) -> Result<String> {
    let x = media::sha256_hex(&blob);
    let mut last_err = anyhow!("no Blossom servers configured");
    for server in &b.config.bridge.blossom_servers {
        let endpoint = format!("{}/upload", server.trim_end_matches('/'));
        let res = b
            .http
            .put(&endpoint)
            .header("Authorization", blossom_auth(keys, &x)?)
            .header("Content-Type", "application/octet-stream")
            .timeout(Duration::from_secs(120))
            .body(blob.clone())
            .send()
            .await;
        match res {
            Ok(r) if r.status().is_success() => {
                let desc: serde_json::Value = r.json().await.unwrap_or_default();
                return Ok(desc
                    .get("url")
                    .and_then(|u| u.as_str())
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("{}/{x}", server.trim_end_matches('/'))));
            }
            Ok(r) => last_err = anyhow!("{server}: {}", r.status()),
            Err(e) => last_err = anyhow!("{server}: {e}"),
        }
    }
    Err(last_err)
}

/// Encrypt a file the way Armada does, upload it, and describe it as an imeta.
pub async fn upload_attachment(b: &Bridge, keys: &Keys, plain: &[u8], mime: &str, dim: Option<(u32, u32)>, alt: Option<&str>) -> Result<Imeta> {
    let (blob, key) = media::encrypt(plain);
    let x = media::sha256_hex(&blob);
    let url = upload_blob(b, keys, blob).await?;
    Ok(Imeta {
        url,
        mime: Some(mime.to_owned()),
        x: Some(x),
        ox: Some(media::sha256_hex(plain)),
        size: Some(plain.len() as u64),
        dim,
        alt: alt.map(str::to_owned),
        encryption: Some(key),
        ..Default::default()
    })
}

/// The Matrix msgtype for a MIME type.
pub fn msgtype(mime: &str) -> &'static str {
    match mime.split('/').next() {
        Some("image") => "m.image",
        Some("video") => "m.video",
        Some("audio") => "m.audio",
        _ => "m.file",
    }
}
