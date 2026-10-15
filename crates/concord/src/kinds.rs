//! Event kinds — CORD-02 Appendix B (frozen), plus Armada's extensions.

pub const WRAP: u16 = 1059;
pub const WRAP_EPHEMERAL: u16 = 21059;
pub const SEAL_ENCRYPTED: u16 = 20013;
pub const SEAL_PLAINTEXT: u16 = 20014;
/// Standard NIP-59 seal (Direct Invites only).
pub const NIP59_SEAL: u16 = 13;

// Chat plane
pub const MESSAGE: u16 = 9;
pub const COMMENT: u16 = 1111;
pub const REACTION: u16 = 7;
pub const DELETE: u16 = 5;
pub const EDIT: u16 = 3302;
pub const TIMER_NOTICE: u16 = 1740;
pub const WEBXDC: u16 = 3310;
pub const TYPING: u16 = 23311;
pub const VOICE_PRESENCE: u16 = 23313;
// Armada extensions on the chat plane (CORD.md)
pub const ZAP: u16 = 9735;
pub const ONCHAIN_ZAP: u16 = 8333;
pub const POLL: u16 = 1068;
pub const POLL_VOTE: u16 = 1018;
pub const CALENDAR_DATE: u16 = 31922;
pub const CALENDAR_TIME: u16 = 31923;
pub const CALENDAR_RSVP: u16 = 31925;

// Guestbook plane
pub const JOIN_LEAVE: u16 = 3306;
pub const KICK: u16 = 3309;
pub const SNAPSHOT: u16 = 3312;

// Control and rekey planes
pub const CONTROL: u16 = 3308;
pub const REKEY: u16 = 3303;

// Person-addressed
pub const DIRECT_INVITE: u16 = 3313;

// Bare events
pub const INVITE_BUNDLE: u16 = 33301;
pub const COMMUNITY_LIST_FRAG: u16 = 33302;
pub const INVITE_LIST: u16 = 13303;
/// Bot command manifest (Armada NIP.md).
pub const BOT_MANIFEST: u16 = 10304;

// Control edition sub-kinds (`vsk`)
pub const VSK_METADATA: &str = "0";
pub const VSK_ROLE: &str = "1";
pub const VSK_CHANNEL: &str = "2";
pub const VSK_GRANT: &str = "3";
pub const VSK_BANLIST: &str = "4";
pub const VSK_INVITE_REGISTRY: &str = "8";
pub const VSK_DISSOLVED: &str = "10";
pub const VSK_PINS: &str = "11";
pub const VSK_SIGNALS: &str = "12";
pub const VSK_INVITE_LIVE: &str = "6";
pub const VSK_INVITE_REVOKED: &str = "9";

pub const SIGNAL_PAUSE: &str = "pause";

/// Which plane a stream belongs to; each has fixed rumor kinds and seal form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Plane {
    Control,
    Chat,
    Guestbook,
    Rekey,
}

impl Plane {
    pub fn seal_kind(self) -> u16 {
        match self {
            Plane::Control => SEAL_PLAINTEXT,
            _ => SEAL_ENCRYPTED,
        }
    }

    /// Whether a rumor kind may ride this plane. Chat refuses every other plane's
    /// kinds, or one channel's key-holder could forge control/guestbook rumors.
    pub fn admits(self, kind: u16) -> bool {
        match self {
            Plane::Control => kind == CONTROL,
            Plane::Guestbook => matches!(kind, JOIN_LEAVE | KICK | SNAPSHOT),
            Plane::Rekey => kind == REKEY,
            Plane::Chat => !matches!(kind, CONTROL | JOIN_LEAVE | KICK | SNAPSHOT | REKEY),
        }
    }
}
