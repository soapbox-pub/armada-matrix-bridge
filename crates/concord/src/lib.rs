//! Concord (CORD-01..08), the protocol behind Armada's end-to-end encrypted
//! communities, as a sans-IO library: nothing here opens a socket or touches a
//! database. Functions take events and key material and return events and state.
//!
//! Byte-compatibility with Armada is the whole point, so every wire-format
//! module is a port of Armada's `src/concord/lib`, checked against vectors that
//! Armada's own code generates (`tools/vectors`).

pub mod chat;
pub mod community;
pub mod control;
pub mod derive;
pub mod direct_invite;
pub mod edition;
pub mod guestbook;
pub mod invite;
pub mod kinds;
pub mod media;
pub mod nip44;
pub mod rekey;
pub mod roles;
pub mod rumor;
pub mod stream;

pub use nostr;

/// A raw 32-byte id or key.
pub type Bytes32 = [u8; 32];

/// Lowercase hex of a byte slice.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Parse exactly 64 hex characters (either case) into 32 bytes.
pub fn hex32(s: &str) -> Option<Bytes32> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// Whether `s` is 64 hex characters.
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A tag number per CORD-01 §Encoding: decimal, no leading zeros, no sign.
pub fn parse_tag_decimal(s: &str) -> Option<u64> {
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
