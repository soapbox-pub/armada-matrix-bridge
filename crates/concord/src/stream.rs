//! Private Streams — CORD-01. A stream event reverses NIP-59: a fixed author (the
//! plane's derived key), an ephemeral `p`, and encryption under the stream's
//! self-ECDH conversation key. Inside rides a seal signed by the real author
//! around an unsigned rumor:
//!
//! ```text
//! wrap(1059/21059, signed by the stream key)
//!   └ seal(20013 encrypted | 20014 plaintext, signed by the author)
//!       └ rumor(unsigned, the functional kind)
//! ```

use nostr::prelude::{Event, Keys, Kind, PublicKey, SecretKey, Tag, Timestamp, UnsignedEvent};
use nostr::event::FinalizeEvent;

use crate::derive::GroupKey;
use crate::kinds::{self, Plane};
use crate::nip44;
use crate::rumor::Rumor;
use crate::Bytes32;

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("not a stream wrap")]
    BadWrapKind,
    #[error("wrap author is not this stream's address")]
    WrongStream,
    #[error("write-restricted wrap signature invalid")]
    BadWrapSignature,
    #[error("decrypt failed: {0}")]
    Decrypt(#[from] nip44::Nip44Error),
    #[error("malformed json: {0}")]
    Parse(String),
    #[error("unknown seal kind {0}")]
    BadSealKind(u16),
    #[error("seal signature invalid")]
    BadSealSignature,
    #[error("rumor author does not match the seal's signer")]
    AuthorMismatch,
    #[error("rumor id is not its event hash")]
    BadRumorId,
    #[error("malformed ms tag")]
    BadMs,
    #[error("rumor kind {0} does not belong on this plane")]
    WrongPlane(u16),
    #[error("channel/epoch binding mismatch")]
    BindingMismatch,
    #[error("signing failed: {0}")]
    Sign(String),
}

/// A stream as a reader holds it: address and read key, plus the wrap-signing
/// secret when held. A write-restricted stream (the split Control Plane) gives
/// members the address and read key only, and its wrap signatures must be checked.
#[derive(Clone)]
pub struct StreamKey {
    pub pk: PublicKey,
    pub conv_key: Bytes32,
    pub sk: Option<SecretKey>,
    pub restricted: bool,
}

impl StreamKey {
    pub fn pk_hex(&self) -> String {
        self.pk.to_hex()
    }
}

impl From<&GroupKey> for StreamKey {
    fn from(g: &GroupKey) -> Self {
        StreamKey { pk: g.pubkey(), conv_key: g.conv_key, sk: Some(g.keys.secret_key().clone()), restricted: false }
    }
}

impl From<GroupKey> for StreamKey {
    fn from(g: GroupKey) -> Self {
        (&g).into()
    }
}

impl std::fmt::Debug for StreamKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamKey")
            .field("pk", &self.pk.to_hex())
            .field("writable", &self.sk.is_some())
            .field("restricted", &self.restricted)
            .finish()
    }
}

/// Seal a rumor with the author's real identity.
pub fn seal_rumor(rumor: &Rumor, seal_kind: u16, conv_key: &Bytes32, author: &Keys) -> Result<Event, StreamError> {
    let json = rumor.to_json();
    let content = if seal_kind == kinds::SEAL_ENCRYPTED { nip44::encrypt_str(conv_key, &json)? } else { json };
    UnsignedEvent::new(author.public_key(), Timestamp::from(rumor.created_at), Kind::Custom(seal_kind), Vec::<Tag>::new(), content)
        .finalize(author)
        .map_err(|e| StreamError::Sign(e.to_string()))
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WrapOptions {
    pub ephemeral: bool,
    /// NIP-40 deadline on the wrap so relays purge it (CORD-08 §2).
    pub expiration: Option<u64>,
}

/// Wrap a signed seal into the outer stream event, signed by the stream key.
pub fn wrap_seal(seal: &Event, stream: &StreamKey, opts: WrapOptions) -> Result<Event, StreamError> {
    let sk = stream.sk.clone().ok_or_else(|| StreamError::Sign("stream key is read-only".into()))?;
    let keys = Keys::new(sk);
    let ephemeral = Keys::generate();
    let mut tags = vec![Tag::parse(["p".to_string(), ephemeral.public_key().to_hex()]).expect("valid p tag")];
    if let Some(exp) = opts.expiration {
        tags.push(Tag::parse(["expiration".to_string(), exp.to_string()]).expect("valid tag"));
    }
    let kind = if opts.ephemeral { kinds::WRAP_EPHEMERAL } else { kinds::WRAP };
    let content = nip44::encrypt_str(&stream.conv_key, &seal.as_json())?;
    UnsignedEvent::new(keys.public_key(), Timestamp::now(), Kind::Custom(kind), tags, content)
        .finalize(&keys)
        .map_err(|e| StreamError::Sign(e.to_string()))
}

/// Seal and wrap in one step.
pub fn seal_and_wrap(rumor: &Rumor, plane: Plane, stream: &StreamKey, author: &Keys, opts: WrapOptions) -> Result<Event, StreamError> {
    let seal = seal_rumor(rumor, plane.seal_kind(), &stream.conv_key, author)?;
    wrap_seal(&seal, stream, opts)
}

/// A fully opened, verified stream event.
#[derive(Clone, Debug)]
pub struct Opened {
    pub rumor: Rumor,
    /// The ordering time in ms.
    pub ms: u64,
    pub seal: Event,
    pub wrap_id: String,
    pub stream_pk: String,
}

impl Opened {
    /// The verified real author (the seal's signer, equal to the rumor's pubkey).
    pub fn author(&self) -> &str {
        &self.rumor.pubkey
    }

    pub fn seal_kind(&self) -> u16 {
        self.seal.kind.as_u16()
    }
}

/// Open and verify one stream wrap:
/// 1. the wrap's author must be the stream address (and on write-restricted
///    streams its signature must verify — the write gate);
/// 2. decrypt to the seal, check its kind and signature;
/// 3. recover the rumor, check its pubkey equals the seal's and its id is its hash.
pub fn open_wrap(wrap: &Event, stream: &StreamKey) -> Result<Opened, StreamError> {
    let kind = wrap.kind.as_u16();
    if kind != kinds::WRAP && kind != kinds::WRAP_EPHEMERAL {
        return Err(StreamError::BadWrapKind);
    }
    if wrap.pubkey != stream.pk {
        return Err(StreamError::WrongStream);
    }
    if stream.restricted && wrap.verify().is_err() {
        return Err(StreamError::BadWrapSignature);
    }
    let seal_json = nip44::decrypt_str(&stream.conv_key, &wrap.content)?;
    let seal = Event::from_json(&seal_json).map_err(|e| StreamError::Parse(e.to_string()))?;
    let seal_kind = seal.kind.as_u16();
    if seal_kind != kinds::SEAL_ENCRYPTED && seal_kind != kinds::SEAL_PLAINTEXT {
        return Err(StreamError::BadSealKind(seal_kind));
    }
    if seal.verify().is_err() {
        return Err(StreamError::BadSealSignature);
    }
    let rumor_json =
        if seal_kind == kinds::SEAL_ENCRYPTED { nip44::decrypt_str(&stream.conv_key, &seal.content)? } else { seal.content.clone() };
    let rumor: Rumor = serde_json::from_str(&rumor_json).map_err(|e| StreamError::Parse(e.to_string()))?;
    if rumor.pubkey != seal.pubkey.to_hex() {
        return Err(StreamError::AuthorMismatch);
    }
    if !rumor.id_is_valid() {
        return Err(StreamError::BadRumorId);
    }
    let ms = rumor.time_ms().map_err(|_| StreamError::BadMs)?;
    Ok(Opened { rumor, ms, seal, wrap_id: wrap.id.to_hex(), stream_pk: wrap.pubkey.to_hex() })
}

/// [`open_wrap`] plus the plane rules: the seal form and rumor kinds the plane
/// admits (CORD-02 §5), so one plane's key-holder can't forge another's rumors.
pub fn open_plane_wrap(wrap: &Event, stream: &StreamKey, plane: Plane) -> Result<Opened, StreamError> {
    let opened = open_wrap(wrap, stream)?;
    if opened.seal_kind() != plane.seal_kind() {
        return Err(StreamError::BadSealKind(opened.seal_kind()));
    }
    if !plane.admits(opened.rumor.kind) {
        return Err(StreamError::WrongPlane(opened.rumor.kind));
    }
    Ok(opened)
}

/// Re-wrap a verified plaintext seal into another stream (compaction, CORD-06).
pub fn rewrap_seal(seal: &Event, target: &StreamKey) -> Result<Event, StreamError> {
    if seal.kind.as_u16() != kinds::SEAL_PLAINTEXT {
        return Err(StreamError::BadSealKind(seal.kind.as_u16()));
    }
    wrap_seal(seal, target, WrapOptions::default())
}

/// The binding tags a Chat rumor MUST commit (CORD-03 §3).
pub fn channel_binding_tags(channel_id_hex: &str, epoch: u64) -> Vec<Vec<String>> {
    vec![vec!["channel".into(), channel_id_hex.into()], vec!["epoch".into(), epoch.to_string()]]
}

/// Enforce the Chat-plane binding: the rumor's committed channel and epoch must
/// strict-equal the coordinate whose key opened it, each tag present exactly once.
pub fn check_channel_binding(rumor: &Rumor, channel_id_hex: &str, epoch: u64) -> Result<(), StreamError> {
    fn unique<'a>(rumor: &'a Rumor, name: &str) -> Result<Option<&'a str>, StreamError> {
        let mut found = None;
        for t in rumor.tags.iter().filter(|t| t.first().is_some_and(|n| n == name)) {
            if found.is_some() {
                return Err(StreamError::BindingMismatch);
            }
            found = Some(t.get(1).map(String::as_str).unwrap_or(""));
        }
        Ok(found)
    }
    if unique(rumor, "channel")? != Some(channel_id_hex) {
        return Err(StreamError::BindingMismatch);
    }
    if unique(rumor, "epoch")? != Some(epoch.to_string().as_str()) {
        return Err(StreamError::BindingMismatch);
    }
    Ok(())
}
