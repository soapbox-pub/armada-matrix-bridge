//! Configuration: a TOML file (`config.toml`) plus the generated appservice
//! registration, which holds the tokens shared with the homeserver.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub homeserver: Homeserver,
    pub appservice: Appservice,
    pub database: Database,
    pub bridge: Bridge,
    #[serde(default)]
    pub encryption: Encryption,
    /// MXID, `@*:server` domain, or `*` → permission level.
    #[serde(default)]
    pub permissions: BTreeMap<String, Permission>,
    #[serde(default)]
    pub logging: Logging,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Homeserver {
    /// How the bridge reaches the homeserver's client-server API.
    pub url: String,
    pub server_name: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Appservice {
    #[serde(default = "default_id")]
    pub id: String,
    /// Where the appservice listens.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// How the homeserver reaches the appservice.
    pub url: String,
    #[serde(default = "default_bot_localpart")]
    pub bot_localpart: String,
    #[serde(default = "default_bot_displayname")]
    pub bot_displayname: String,
    #[serde(default)]
    pub bot_avatar: Option<String>,
    /// Armada members appear as `@<prefix><npub>:server`.
    #[serde(default = "default_ghost_prefix")]
    pub ghost_prefix: String,
    #[serde(default = "default_registration")]
    pub registration: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Database {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Bridge {
    /// 64 hex characters. Derives every Matrix user's Armada key and the key that
    /// seals community secrets at rest. Losing it loses those identities.
    pub master_secret: String,
    /// The bridge's own Armada identity (nsec or hex). Derived from the master
    /// secret when unset.
    #[serde(default)]
    pub nostr_key: Option<String>,
    /// Relays for profiles, the bot's DM inbox, and Blossom upload discovery.
    #[serde(default = "default_relays")]
    pub relays: Vec<String>,
    #[serde(default = "default_blossom")]
    pub blossom_servers: Vec<String>,
    #[serde(default = "default_prefix")]
    pub command_prefix: String,
    /// The base used for links to Armada in notices.
    #[serde(default = "default_armada_web")]
    pub armada_web: String,
    /// Suffix appended to Matrix users' display names on Armada.
    #[serde(default = "default_puppet_suffix")]
    pub puppet_name_suffix: String,
    /// Suffix appended to Armada members' display names on Matrix.
    #[serde(default = "default_ghost_suffix")]
    pub ghost_name_suffix: String,
    /// Largest attachment bridged in either direction, in bytes.
    #[serde(default = "default_max_media")]
    pub max_media_bytes: u64,
    /// How far back to backfill a newly bridged channel.
    #[serde(default = "default_backfill")]
    pub backfill_messages: usize,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Encryption {
    /// Support end-to-end encrypted Matrix rooms (needs MSC2409, MSC3202, MSC4190).
    #[serde(default)]
    pub enabled: bool,
    /// Create new portal rooms encrypted.
    #[serde(default)]
    pub default: bool,
    #[serde(default = "default_crypto_dir")]
    pub store_dir: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Logging {
    #[serde(default = "default_log")]
    pub filter: String,
}

impl Default for Logging {
    fn default() -> Self {
        Logging { filter: default_log() }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    /// Messages are not bridged.
    None,
    /// Messages are bridged under the user's own Armada puppet.
    User,
    /// May bridge and unbridge communities.
    Admin,
}

fn default_id() -> String {
    "armada".into()
}
fn default_bind() -> String {
    "127.0.0.1:8789".into()
}
fn default_bot_localpart() -> String {
    "armadabot".into()
}
fn default_bot_displayname() -> String {
    "Armada bridge".into()
}
fn default_ghost_prefix() -> String {
    "armada_".into()
}
fn default_registration() -> PathBuf {
    "registration.yaml".into()
}
fn default_max_connections() -> u32 {
    10
}
fn default_relays() -> Vec<String> {
    ["wss://relay.ditto.pub", "wss://relay.primal.net", "wss://relay.damus.io"].map(String::from).to_vec()
}
fn default_blossom() -> Vec<String> {
    ["https://blossom.ditto.pub", "https://blossom.primal.net"].map(String::from).to_vec()
}
fn default_prefix() -> String {
    "!armada".into()
}
fn default_armada_web() -> String {
    "https://armada.buzz".into()
}
fn default_puppet_suffix() -> String {
    " (Matrix)".into()
}
fn default_ghost_suffix() -> String {
    " (Armada)".into()
}
fn default_max_media() -> u64 {
    50 * 1024 * 1024
}
fn default_backfill() -> usize {
    50
}
fn default_crypto_dir() -> PathBuf {
    "crypto".into()
}
fn default_log() -> String {
    "info,armada_matrix=debug".into()
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: Config = toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        if concord::hex32(&config.bridge.master_secret).is_none() {
            bail!("bridge.master_secret must be 64 hex characters (generate one with `openssl rand -hex 32`)");
        }
        config.homeserver.url = config.homeserver.url.trim_end_matches('/').to_owned();
        if config.appservice.registration.is_relative()
            && let Some(dir) = path.parent()
        {
            config.appservice.registration = dir.join(&config.appservice.registration);
        }
        Ok(config)
    }

    pub fn master_secret(&self) -> [u8; 32] {
        concord::hex32(&self.bridge.master_secret).expect("validated at load")
    }

    pub fn bot_mxid(&self) -> String {
        format!("@{}:{}", self.appservice.bot_localpart, self.homeserver.server_name)
    }

    /// The permission level of a Matrix user: exact MXID, then server, then `*`.
    pub fn permission(&self, mxid: &str) -> Permission {
        if let Some(p) = self.permissions.get(mxid) {
            return *p;
        }
        if let Some((_, server)) = mxid.split_once(':')
            && let Some(p) = self.permissions.get(server)
        {
            return *p;
        }
        self.permissions.get("*").copied().unwrap_or(Permission::None)
    }
}

/// The appservice registration shared with the homeserver.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Registration {
    pub id: String,
    pub url: String,
    pub as_token: String,
    pub hs_token: String,
    pub sender_localpart: String,
}

impl Registration {
    pub fn generate(config: &Config) -> String {
        let token = || hex::encode(rand::random::<[u8; 32]>());
        let server = regex_escape(&config.homeserver.server_name);
        let prefix = regex_escape(&config.appservice.ghost_prefix);
        format!(
            "# Generated by armada-matrix. Give this file to your homeserver and keep it secret.\n\
             id: {id}\n\
             url: {url}\n\
             as_token: {as_token}\n\
             hs_token: {hs_token}\n\
             sender_localpart: {bot}\n\
             rate_limited: false\n\
             namespaces:\n\
             \x20 users:\n\
             \x20   - regex: '@{prefix}npub1[a-z0-9]+:{server}'\n\
             \x20     exclusive: true\n\
             \x20   - regex: '@{bot}:{server}'\n\
             \x20     exclusive: true\n\
             \x20 aliases: []\n\
             \x20 rooms: []\n\
             # Typing notifications and, with encryption, to-device events and key counts.\n\
             de.sorunome.msc2409.push_ephemeral: true\n\
             receive_ephemeral: true\n\
             org.matrix.msc3202: true\n\
             io.element.msc4190: true\n",
            id = config.appservice.id,
            url = config.appservice.url,
            as_token = token(),
            hs_token = token(),
            bot = config.appservice.bot_localpart,
        )
    }

    pub fn load(path: &Path) -> Result<Registration> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("reading {} (run `armada-matrix generate-registration` first)", path.display()))?;
        let get = |key: &str| -> Result<String> {
            raw.lines()
                .find_map(|l| l.strip_prefix(&format!("{key}:")).map(|v| v.trim().trim_matches(['\'', '"']).to_owned()))
                .with_context(|| format!("{} has no `{key}`", path.display()))
        };
        Ok(Registration { id: get("id")?, url: get("url")?, as_token: get("as_token")?, hs_token: get("hs_token")?, sender_localpart: get("sender_localpart")? })
    }
}

fn regex_escape(s: &str) -> String {
    s.chars().flat_map(|c| if "\\.+*?()|[]{}^$".contains(c) { vec!['\\', c] } else { vec![c] }).collect()
}
