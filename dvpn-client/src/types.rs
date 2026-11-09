//! Answers of the node's API (`doc/api.md`). Times are unix seconds, keys base64url strings,
//! addresses `ip:port` strings unless said otherwise. Fields a newer node adds are ignored.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The node's answer to `init`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct InitInfo {
    /// The API versions the node serves.
    pub version: u64,
    pub min_version: u64,
    pub key: String,
    pub name: String,
    /// Group id, and its local name.
    pub group: String,
    pub group_name: String,
    /// The node holds the group secret.
    pub admin: bool,
    pub node_version: String,
}

/// `get status`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Status {
    pub key: String,
    pub name: String,
    pub group: String,
    pub group_name: String,
    pub admin: bool,
    /// Addresses and subnets from the certificate.
    pub prefixes: Vec<String>,
    /// The node's IPv6 address in the group.
    pub ula: String,
    pub relay: bool,
    pub cert_days: u64,
    /// psk epoch.
    pub epoch: u32,
    pub servers: Vec<ServerState>,
    /// Names of the gateways in use.
    pub exit_v4: Option<String>,
    pub exit_v6: Option<String>,
    pub kill_switch: bool,
    pub local_addr: Option<String>,
    pub uptime_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerState {
    pub addr: String,
    pub connected: bool,
}

/// One of `get neighbors`: a node with a direct session.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Neighbor {
    pub key: String,
    pub name: Option<String>,
    pub endpoint: Option<String>,
    pub rtt_ms: Option<f64>,
    pub alive: bool,
    pub session_secs: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

/// `get routes`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Routes {
    pub mesh: Vec<MeshRoute>,
    pub ckr: Vec<CkrRoute>,
    /// How many there are in all (the lists may be a part: `offset` / `limit`).
    pub mesh_total: Option<u64>,
    pub ckr_total: Option<u64>,
}

/// To `key` through the neighbour `via`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct MeshRoute {
    pub key: String,
    pub name: Option<String>,
    pub via: String,
    pub via_name: Option<String>,
    pub cost: u32,
}

/// A network and where it goes: a member's name (or short key), or what the node does with it.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct CkrRoute {
    pub net: String,
    pub to: String,
    /// Also a route of the system.
    pub system: bool,
}

/// A hop of `get path`; the last one is the member itself.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Hop {
    pub key: String,
    pub name: Option<String>,
}

/// `get ping`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Ping {
    pub rtt_ms: f64,
    pub via: Via,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum Via {
    Direct,
    Relays,
}

/// Enums that come as strings. rmpv takes enums apart as msgpack encodes them (an index or a
/// map), not as strings, so these go through a `String`.
macro_rules! from_string {
    ($t:ty { $($s:literal => $v:expr,)* }) => {
        impl TryFrom<String> for $t {
            type Error = String;

            fn try_from(s: String) -> Result<Self, String> {
                match s.as_str() {
                    $($s => Ok($v),)*
                    other => Err(format!("{other:?}: not a {}", stringify!($t))),
                }
            }
        }
    };
}

from_string!(Via { "direct" => Via::Direct, "relays" => Via::Relays, });

/// `get metrics`: counters since the node started.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Metrics {
    pub uptime_secs: u64,
    pub handshakes: u64,
    /// Forwarded for others (as a relay).
    pub relayed: Counter,
    /// Dropped packets by reason.
    pub drops: BTreeMap<String, u64>,
    pub peers: Vec<PeerMetrics>,
    /// How many `peers` there are in all (the list may be a part).
    pub peers_total: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct PeerMetrics {
    pub key: String,
    pub name: Option<String>,
    /// IP traffic with the member, any path.
    pub ip_tx: Counter,
    pub ip_rx: Counter,
    /// Packets of the direct session with it.
    pub wire_tx: Counter,
    pub wire_rx: Counter,
}

/// `get version`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Version {
    pub api: u64,
    pub api_min: u64,
    /// The node program.
    pub node: String,
    /// The protocol on the wire (`dvpn/4`).
    pub wire: String,
}

/// `get group`: the group as the node sees it, without secrets.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub admin: bool,
    /// The psk epoch the node sends with.
    pub epoch: u32,
    /// Until when the previous psk is still accepted after a change.
    pub prev_epoch_until: Option<u64>,
    /// An announced psk change not switched to yet.
    pub next_epoch: Option<NextEpoch>,
    pub cert: OwnCert,
    pub obfs: Obfs,
    pub servers: Vec<Server>,
    pub statics: Vec<StaticPeer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct NextEpoch {
    pub epoch: u32,
    /// When everybody switches to it.
    pub at: u64,
    /// That time has come.
    pub started: bool,
    /// The node has the new psk (without it, it loses the group once the switch comes).
    pub has_key: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct OwnCert {
    pub not_after: u64,
    pub days: u64,
    /// Still the certificate from the invite (an admin has not seen this node online yet).
    pub invite: bool,
}

/// The masking profile: sizes and counts (`[min, max]`).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Obfs {
    pub junk_count: (u64, u64),
    pub junk_size: (u64, u64),
    pub signatures: u64,
    pub init_pad: (u64, u64),
    pub resp_pad: (u64, u64),
    pub data_pad: (u64, u64),
}

/// A discovery server.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Server {
    pub addr: String,
    pub key: String,
    pub connected: bool,
}

/// A node of `[[static_peers]]`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct StaticPeer {
    pub key: String,
    pub name: Option<String>,
    pub endpoints: Vec<String>,
    pub direct: bool,
}

/// One of `get members`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Member {
    pub key: String,
    /// None: revoked before the node ever saw its certificate.
    pub name: Option<String>,
    /// Addresses of the node (/32, /128).
    pub addrs: Vec<String>,
    /// Subnets behind it.
    pub routes: Vec<String>,
    /// `admin`, `relay`, `exit_v4`, `exit_v6`.
    pub roles: Vec<String>,
    pub not_after: Option<u64>,
    pub days: Option<u64>,
    pub expired: bool,
    /// Still the certificate from the invite.
    pub invite: bool,
    pub revoked: bool,
    /// The node answering.
    #[serde(rename = "self")]
    pub is_self: bool,
    /// Reachable now, directly or through relays.
    pub online: bool,
    /// A live direct link.
    pub direct: bool,
}

impl Member {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// `get exit` (and the answer to `set exit`).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Exit {
    pub v4: Vec<Gateway>,
    pub v6: Vec<Gateway>,
    pub kill_switch: bool,
    pub dns: Vec<String>,
    /// Only these sources go through the gateway (both families).
    pub sources: Vec<String>,
    pub table: Option<u32>,
    /// Only the destinations listed in this file go through the gateway (None: the whole
    /// internet); how many it lists as in use, and why it could not be read last time.
    #[serde(default)]
    pub only_file: Option<String>,
    #[serde(default)]
    pub only_count: usize,
    #[serde(default)]
    pub only_error: Option<String>,
    /// The gateway in use now.
    pub active: PerFamily<Option<ActiveGateway>>,
    /// The kill switch blocks the internet: gateways configured, none alive.
    pub blocked: PerFamily<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct PerFamily<T> {
    pub v4: T,
    pub v6: T,
}

/// A gateway of `[exit]`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Gateway {
    /// As written in `[exit]`: a name or a key.
    pub gateway: String,
    /// Who that is (None: no such member known).
    pub key: Option<String>,
    pub name: Option<String>,
    pub alive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ActiveGateway {
    pub key: String,
    pub name: Option<String>,
}

/// Changes for `set exit`; fields left `None` stay as they are.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitUpdate {
    /// Remove all of `[exit]` first.
    pub clear: bool,
    /// Gateways by priority, names or keys (empty: none).
    pub v4: Option<Vec<String>>,
    pub v6: Option<Vec<String>>,
    /// `Some(None)`: back to the default (on).
    pub kill_switch: Option<Option<bool>>,
    pub dns: Option<Vec<String>>,
    pub sources: Option<Vec<String>>,
    /// `Some(None)`: no table of its own.
    pub table: Option<Option<u32>>,
    /// A full path, read by the node; `Some(None)`: the whole internet again.
    pub only_file: Option<Option<String>>,
}

/// One forwarded port of a gateway.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ForwardRule {
    /// `tcp`, `udp` or `both`.
    pub proto: String,
    /// The port on the gateway.
    pub port: u16,
    /// The member: name or key.
    pub to: String,
    /// The member's name, when `to` is a key of a known one.
    #[serde(default)]
    pub name: Option<String>,
    pub to_port: u16,
    /// The member sees the client's address (needs this gateway as its exit).
    pub keep_ip: bool,
}

/// `get forward`: the ports forwarded on a gateway.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Forwards {
    /// An admin's rules are applied on this node.
    pub allow_remote: bool,
    /// `[[gateway.forward]]` of this node.
    pub local: Vec<ForwardRule>,
    /// Set by admins (with `on`: for that gateway).
    pub remote: Vec<ForwardRule>,
}

/// `get acl`: the group's access rules.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Acl {
    /// An admin set rules (false: everybody may reach everybody).
    pub set: bool,
    /// `allow` or `deny`.
    pub default: String,
    /// As `dvpn acl show` prints it (names for keys).
    pub toml: String,
    pub tags: BTreeMap<String, Vec<String>>,
    pub rules: Vec<AclRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct AclRule {
    /// Names, tags or `*`.
    pub from: Vec<String>,
    pub to: Vec<String>,
    /// `any`, `tcp`, `udp`, `icmp`.
    pub proto: String,
    /// Port ranges, inclusive.
    pub ports: Vec<(u16, u16)>,
    pub allow: bool,
}

/// What an invite is for (`set invite`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InviteRequest {
    /// The new node's name.
    pub name: String,
    /// Its IPv4 address (None: a free one in the group network).
    pub addr: Option<String>,
    /// How long the invite can be used (None: the node's default, 24 h).
    pub ttl_hours: Option<u64>,
    /// The admin node's fixed addresses (`host:port`) the new node connects to directly.
    pub statics: Vec<String>,
    /// Subnets behind the new node.
    pub routes: Vec<String>,
    pub relay: bool,
}

/// A made invite.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct InviteMade {
    /// For the new node (`dvpn group join`): a secret, pass it on privately.
    pub invite: String,
    pub name: String,
    pub addr: String,
    /// Usable until (unix seconds).
    pub until: u64,
    pub warnings: Vec<String>,
}

/// Changes to a member (`set node`); `None` / empty: unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeChange {
    pub name: Option<String>,
    pub addr: Option<String>,
    pub add_routes: Vec<String>,
    pub del_routes: Vec<String>,
    pub relay: Option<bool>,
}

/// A member's new certificate.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct NodeCert {
    pub key: String,
    pub name: String,
    pub prefixes: Vec<String>,
    pub relay: bool,
    pub not_after: u64,
}

/// A revoked member, and the psk change that came with it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Revoked {
    pub key: String,
    pub name: Option<String>,
    pub epoch: Option<u32>,
    pub at: Option<u64>,
}

/// A psk change: epoch `epoch` from `at`, sealed to `sealed_to` members.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Rotated {
    pub epoch: u32,
    pub at: u64,
    pub sealed_to: u64,
}

/// What the node tells as it happens (`sub`, [`crate::Client::events`]).
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Event {
    /// A local peer record added, updated or deleted (v2-style; prefer `Member` / `Neighbor`).
    Peer { action: String, key: String, name: Option<String>, addr: Option<String>, endpoint: Option<(String, u16)> },
    /// A discovery server connected or lost.
    Server { server: (String, u16), status: bool },
    /// A new RTT measurement.
    Ping { key: String, ping: f64 },
    /// A direct link came up, went down, or moved to another endpoint.
    Neighbor { key: String, name: Option<String>, state: NeighborState, endpoint: Option<String> },
    /// The first hop to a member changed; `via` None: no route now.
    Route { key: String, name: Option<String>, via: Option<String>, via_name: Option<String> },
    /// The gateways in use or the kill switch changed.
    Exit { active: PerFamily<Option<ActiveGateway>>, blocked: PerFamily<bool> },
    /// A member joined, changed (name, addresses, roles) or was revoked.
    Member { action: MemberAction, key: String, name: Option<String>, prefixes: Vec<String>, revoked: bool },
    /// A psk change was announced (`next`) or switched to (`epoch`).
    Epoch { epoch: u32, next: Option<EpochAt> },
    /// Counters, every `metrics_secs` (only if subscribed).
    Metrics(Metrics),
    /// A line of the node's log (only if subscribed), at the subscribed level and above.
    Log { level: LogLevel, time: f64, text: String },
    /// A kind this version does not know.
    #[serde(other)]
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum NeighborState {
    Up,
    Down,
    Moved,
}

from_string!(NeighborState { "up" => NeighborState::Up, "down" => NeighborState::Down, "moved" => NeighborState::Moved, });

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum MemberAction {
    Add,
    Update,
    Revoke,
}

from_string!(MemberAction { "add" => MemberAction::Add, "update" => MemberAction::Update, "revoke" => MemberAction::Revoke, });

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub struct EpochAt {
    pub epoch: u32,
    pub at: u64,
}

/// Event kinds for [`crate::Client::subscribe`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventKind {
    Peer,
    Server,
    Ping,
    Neighbor,
    Route,
    Exit,
    Member,
    Epoch,
    Metrics,
    Log,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Peer => "peer",
            EventKind::Server => "server",
            EventKind::Ping => "ping",
            EventKind::Neighbor => "neighbor",
            EventKind::Route => "route",
            EventKind::Exit => "exit",
            EventKind::Member => "member",
            EventKind::Epoch => "epoch",
            EventKind::Metrics => "metrics",
            EventKind::Log => "log",
        }
    }
}

/// Levels of the node's log, most severe first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

from_string!(LogLevel {
    "error" => LogLevel::Error,
    "warn" => LogLevel::Warn,
    "info" => LogLevel::Info,
    "debug" => LogLevel::Debug,
    "trace" => LogLevel::Trace,
});

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

/// What [`crate::Client::subscribe`] asks the node for. The default: all kinds but `metrics`
/// and `log`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Subscription {
    /// Event kinds (empty: the default set).
    pub kinds: Vec<EventKind>,
    /// `metrics` events this often (1..3600 s); adds `Metrics`.
    pub metrics_secs: Option<u64>,
    /// `log` events at this level and above (the node logs only what its `log_level` lets
    /// through); adds `Log`.
    pub log_level: Option<LogLevel>,
}

/// API routes a client may take for its own protocol over the network (`route reg`).
pub const ROUTES: std::ops::RangeInclusive<u8> = 32..=255;

/// The largest packet that goes through relays too (directly: ~1400 bytes).
pub const MAX_PAYLOAD: usize = 1350;

/// A packet of a client's own protocol, from or to a member, on an API route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetPacket {
    pub route: u8,
    /// The member it came from.
    pub key: String,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{from_value, map};
    use rmpv::Value;

    /// Every string enum, straight in an answer and inside an event: the two ways rmpv sees them.
    #[test]
    fn string_enums() {
        let ping: Option<Ping> = from_value(map(vec![("rtt_ms", 2.15.into()), ("via", "relays".into())])).unwrap();
        assert_eq!(ping, Some(Ping { rtt_ms: 2.15, via: Via::Relays }));
        let direct: Ping = from_value(map(vec![("rtt_ms", 1.0.into()), ("via", "direct".into())])).unwrap();
        assert_eq!(direct.via, Via::Direct);
        assert!(from_value::<Ping>(map(vec![("rtt_ms", 1.0.into()), ("via", "pigeon".into())])).is_err());

        let e: Event = from_value(map(vec![
            ("kind", "neighbor".into()),
            ("key", "k".into()),
            ("name", Value::Nil),
            ("state", "moved".into()),
            ("endpoint", "192.0.2.1:5".into()),
        ]))
        .unwrap();
        assert!(matches!(e, Event::Neighbor { state: NeighborState::Moved, .. }));
        let e: Event = from_value(map(vec![
            ("kind", "member".into()),
            ("action", "revoke".into()),
            ("key", "k".into()),
            ("name", "bob".into()),
            ("prefixes", Value::Array(vec![])),
            ("revoked", true.into()),
        ]))
        .unwrap();
        assert!(matches!(e, Event::Member { action: MemberAction::Revoke, .. }));
        let log =
            map(vec![("kind", "log".into()), ("level", "warn".into()), ("time", 1.5.into()), ("text", "x".into())]);
        assert!(matches!(from_value::<Event>(log).unwrap(), Event::Log { level: LogLevel::Warn, .. }));
        let e: Event = from_value(map(vec![("kind", "brand_new".into()), ("x", 1.into())])).unwrap();
        assert_eq!(e, Event::Other);
    }
}
