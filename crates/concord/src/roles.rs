//! Roles and permissions — CORD-04. Read access is key possession; write
//! authority is rank in the owner-rooted Roster. Bit positions are frozen.

use serde_json::Value;

pub mod perm {
    pub const MANAGE_ROLES: u64 = 1 << 0;
    pub const MANAGE_CHANNELS: u64 = 1 << 1;
    pub const MANAGE_METADATA: u64 = 1 << 2;
    pub const KICK: u64 = 1 << 3;
    pub const BAN: u64 = 1 << 4;
    pub const MANAGE_MESSAGES: u64 = 1 << 5;
    pub const CREATE_INVITE: u64 = 1 << 6;
    pub const VIEW_AUDIT_LOG: u64 = 1 << 8;
    pub const MENTION_EVERYONE: u64 = 1 << 9;
    pub const PIN_MESSAGES: u64 = 1 << 11;

    /// Bits whose actions are Control editions; holders are staff (CORD-04 §3).
    pub const STAFF: u64 = MANAGE_ROLES | MANAGE_CHANNELS | MANAGE_METADATA | BAN | CREATE_INVITE | PIN_MESSAGES;
}

pub const NAME_MAX_BYTES: usize = 64;
pub const MAX_ROLES_PER_MEMBER: usize = 64;
pub const MAX_ROLES_PER_COMMUNITY: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoleScope {
    Server,
    Channel(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Role {
    pub role_id: String,
    pub name: String,
    /// Lower is higher authority. Position 0 is the owner's alone, never a Role.
    pub position: u32,
    pub permissions: u64,
    pub scope: RoleScope,
    pub color: u32,
}

impl Role {
    pub fn from_json(json: &str) -> Option<Role> {
        let v: Value = serde_json::from_str(json).ok()?;
        let role_id = v.get("role_id")?.as_str().filter(|s| crate::is_hex64(s))?.to_lowercase();
        let permissions = match v.get("permissions")? {
            Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s.parse().ok()?,
            Value::Number(n) => n.as_u64().or_else(|| n.as_f64().filter(|f| f.is_finite() && *f >= 0.0).map(|f| f.trunc() as u64))?,
            _ => return None,
        };
        let position = v.get("position")?.as_u64().filter(|p| *p >= 1 && *p <= u32::MAX as u64)? as u32;
        let name = v.get("name").and_then(Value::as_str).unwrap_or("").to_owned();
        if name.len() > NAME_MAX_BYTES {
            return None;
        }
        let scope = match v.get("scope") {
            Some(s) if s.get("kind").and_then(Value::as_str) == Some("channel") => match s.get("channel_id").and_then(Value::as_str) {
                Some(id) => RoleScope::Channel(id.to_owned()),
                None => RoleScope::Server,
            },
            _ => RoleScope::Server,
        };
        let color = v.get("color").and_then(Value::as_f64).filter(|c| c.is_finite() && *c >= 0.0 && *c <= u32::MAX as f64).map(|c| c.trunc() as u32).unwrap_or(0);
        Some(Role { role_id, name, position, permissions, scope, color })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberGrant {
    pub member: String,
    pub role_ids: Vec<String>,
    /// The staff write key riding a staff-making Grant (CORD-04 §3), base64.
    pub control_wrap: Option<String>,
}

impl MemberGrant {
    pub fn from_json(json: &str) -> Option<MemberGrant> {
        let v: Value = serde_json::from_str(json).ok()?;
        let member = v.get("member")?.as_str().filter(|s| crate::is_hex64(s))?.to_lowercase();
        let role_ids = v
            .get("role_ids")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|r| r.as_str().map(str::to_owned)).take(MAX_ROLES_PER_MEMBER).collect())
            .unwrap_or_default();
        let control_wrap = v.get("control_wrap").and_then(Value::as_str).filter(|s| !s.is_empty() && s.len() <= 1024).map(str::to_owned);
        Some(MemberGrant { member, role_ids, control_wrap })
    }
}

#[derive(Clone, Debug, Default)]
pub struct Roster {
    pub roles: Vec<Role>,
    pub grants: Vec<MemberGrant>,
}

impl Roster {
    pub fn role(&self, role_id: &str) -> Option<&Role> {
        self.roles.iter().find(|r| r.role_id == role_id)
    }

    pub fn roles_of<'a>(&'a self, member: &'a str) -> impl Iterator<Item = &'a Role> + 'a {
        self.grants.iter().filter(move |g| g.member == member).flat_map(move |g| g.role_ids.iter().filter_map(move |id| self.role(id)))
    }

    pub fn permissions(&self, member: &str) -> u64 {
        self.roles_of(member).fold(0, |acc, r| acc | r.permissions)
    }

    pub fn has(&self, member: &str, bits: u64) -> bool {
        self.permissions(member) & bits == bits
    }

    /// The member's rank: the lowest position among their Roles.
    pub fn highest_position(&self, member: &str) -> Option<u32> {
        self.roles_of(member).map(|r| r.position).min()
    }

    pub fn is_staff(&self, member: &str, owner: &str) -> bool {
        member == owner || self.permissions(member) & perm::STAFF != 0
    }

    /// Owner is supreme; otherwise the actor must hold `bits`.
    pub fn is_authorized(&self, actor: &str, owner: &str, bits: u64) -> bool {
        actor == owner || self.has(actor, bits)
    }

    /// Does the actor strictly outrank `target_position`?
    pub fn outranks(&self, actor: &str, owner: &str, target_position: u32) -> bool {
        actor == owner || self.highest_position(actor).is_some_and(|p| p < target_position)
    }

    pub fn outranks_member(&self, actor: &str, owner: &str, member: &str) -> bool {
        if actor == owner {
            return true;
        }
        if member == owner {
            return false;
        }
        let target = self.highest_position(member).unwrap_or(u32::MAX);
        self.outranks(actor, owner, target)
    }

    pub fn can_act_on_position(&self, actor: &str, owner: &str, position: u32, bits: u64) -> bool {
        actor == owner || (self.has(actor, bits) && self.outranks(actor, owner, position))
    }

    /// The actor holds the bit AND strictly outranks the target; the owner is never a target.
    pub fn can_act_on_member(&self, actor: &str, owner: &str, target: &str, bits: u64) -> bool {
        if target == owner {
            return false;
        }
        let position = self.highest_position(target).unwrap_or(u32::MAX);
        self.can_act_on_position(actor, owner, position, bits)
    }

    /// Whether a member is entitled to a private Channel's key: the owner always,
    /// otherwise via a Role scoped to that Channel.
    pub fn entitled_to_channel(&self, member: &str, owner: &str, channel_id_hex: &str) -> bool {
        member == owner
            || self.roles_of(member).any(|r| matches!(&r.scope, RoleScope::Channel(id) if id.eq_ignore_ascii_case(channel_id_hex)))
    }
}
