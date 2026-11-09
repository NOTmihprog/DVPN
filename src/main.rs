use std::io::{BufRead, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use ipnet::{IpNet, Ipv4Net};
use log::LevelFilter;

#[cfg(windows)]
mod winservice;

use dvpn::{config, logger, ops, tracker_server};

use dvpn::config::{Config, GroupConfig, SOCKET_DEFAULT_ADDR, STATE_FILE_NAME, parse_obfs};
use dvpn::crypto::{encode_b64, random_bytes};
use dvpn::group::{CertBody, GroupSecret, JOIN_TTL_SECS, now_unix};
use dvpn::identity::{Identity, NodeId};
use dvpn::state::{Membership, StateStore};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHOR: &str = "mihprog";
const EMAIL: &str = "mih@mihprog.com";

#[derive(Parser)]
#[command(name = "dvpn", disable_version_flag = true, about = "Decentralized P2P VPN")]
struct Cli {
    /// Directory with config.toml (default: executable directory)
    #[arg(long, global = true, env = "DVPN_DIR")]
    dir: Option<PathBuf>,

    /// Disable network interface
    #[arg(short = 'd', long)]
    disable_net: bool,

    /// API net socket (ip:port) or unix socket path, unix sockets are unsupported on windows
    #[arg(short = 'a', long)]
    api_addr: Option<String>,

    /// Print version and exit
    #[arg(short = 'v', long)]
    version: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a random 32-byte key (base64url), e.g. a node private key
    GenKey,
    /// Print the node public key (node id) from config.toml / DVPN_PRIVATE_KEY
    ShowKey {
        /// Private key to derive the public key from, instead of the configured one
        // base64url keys may start with '-'
        #[arg(short = 'k', long, allow_hyphen_values = true)]
        key: Option<String>,
    },
    /// Groups: create one (this node becomes its admin), invite nodes, join by invite
    #[command(subcommand)]
    Group(GroupCommand),
    /// Members: addresses, subnets and roles (admins change them with `node set`)
    #[command(subcommand)]
    Node(NodeCommand),
    /// Access rules inside the group (admins set them; every node enforces them)
    #[command(subcommand)]
    Acl(AclCommand),
    /// Ports of this gateway, or of another one with --on, that lead to members
    #[command(subcommand)]
    Forward(ForwardCommand),
    /// The running node: key, group, addresses, trackers, gateway (asks its API)
    Status,
    /// Direct neighbours of the running node: endpoint, RTT, session
    Neighbors,
    /// Routes of the running node: mesh (through relays) and CKR (addresses and subnets)
    Routes,
    /// Traffic counters of the running node: per member, relayed, dropped packets by reason
    Metrics,
    /// Round trips to a member over our session with it (direct or through relays)
    Ping {
        /// Member name, node key or key prefix
        #[arg(allow_hyphen_values = true)]
        node: String,
        /// How many
        #[arg(short = 'c', long, default_value_t = 4)]
        count: u32,
    },
    /// The hops to a member through the mesh
    Path {
        /// Member name, node key or key prefix
        #[arg(allow_hyphen_values = true)]
        node: String,
    },
    /// Gateways to the internet, by priority (the first alive one is used), or none.
    /// Without options: show them. A running node follows the change within seconds
    Exit {
        /// IPv4 gateways, best first: member names or node keys, comma separated
        #[arg(long, value_delimiter = ',', allow_hyphen_values = true)]
        v4: Option<Vec<String>>,
        /// IPv6 gateways, best first
        #[arg(long, value_delimiter = ',', allow_hyphen_values = true)]
        v6: Option<Vec<String>>,
        /// No gateway: the internet is reached directly, as without DVPN
        #[arg(long, conflicts_with_all = ["v4", "v6"])]
        none: bool,
        /// With gateways set but none alive: block the internet (on, the default) or let it go
        /// direct (off)
        #[arg(long, value_parser = ["on", "off"])]
        kill_switch: Option<String>,
        /// DNS servers to use through the gateway (comma separated IPs; "none" to clear)
        #[arg(long, value_delimiter = ',')]
        dns: Option<Vec<String>>,
        /// Only these sources go through the gateway (comma separated networks, IPv4 and IPv6;
        /// "none" to clear): the node itself and the rest reach the internet directly
        #[arg(long, value_delimiter = ',')]
        sources: Option<Vec<String>>,
        /// Routing table for the internet routes ("none": DVPN's own). Without --sources DVPN
        /// adds no rule to it: your own rules (fwmark, iif) steer traffic there
        #[arg(long)]
        table: Option<String>,
        /// Only the destinations listed in this file go through the gateway, the rest of the
        /// internet directly ("none": the whole internet). Networks or addresses, separated by
        /// commas, spaces or new lines; the node re-reads the file when it changes
        #[arg(long, value_name = "FILE")]
        only: Option<PathBuf>,
    },
    /// Start peer discovery server
    Server {
        /// Server bind address: "::" = IPv6 and IPv4 on one socket
        #[arg(short = 'a', long, default_value = "::")]
        addr: std::net::IpAddr,
        /// Server bind port
        #[arg(short = 'p', long, default_value_t = 6485)]
        port: u16,
    },
    /// The node as a Windows service: starts with the system, log in dvpn.log next to config.toml
    #[cfg(windows)]
    #[command(subcommand)]
    Service(ServiceCommand),
}

#[cfg(windows)]
#[derive(Subcommand)]
enum ServiceCommand {
    /// Register the service for this directory (--dir) and start it (as Administrator)
    Install,
    /// Stop and remove the service
    Uninstall,
    Start,
    Stop,
    /// Whether the service is installed and running
    Status,
    /// What the service manager runs (not by hand)
    #[command(hide = true)]
    Run,
}

#[derive(Subcommand)]
enum ForwardCommand {
    /// The ports forwarded here, or set by admins for a gateway
    List {
        /// The gateway, if not this node
        #[arg(long, value_name = "MEMBER")]
        on: Option<String>,
    },
    /// Forward a port to a member; a running node follows within seconds
    Add {
        /// The port on the gateway
        port: u16,
        /// The member: name or key
        to: String,
        /// The port on the member (default: the same)
        #[arg(long)]
        to_port: Option<u16>,
        /// tcp, udp or both
        #[arg(long, default_value = "tcp")]
        proto: String,
        /// The member sees the client's address: needs this gateway as its exit
        #[arg(long)]
        keep_ip: bool,
        /// Another gateway (admins only; it must have allow_remote)
        #[arg(long, value_name = "MEMBER")]
        on: Option<String>,
    },
    /// Stop forwarding a port
    Del {
        /// The port on the gateway
        port: u16,
        /// tcp, udp or both
        #[arg(long, default_value = "both")]
        proto: String,
        /// Another gateway (admins only)
        #[arg(long, value_name = "MEMBER")]
        on: Option<String>,
    },
}

#[derive(Subcommand)]
enum AclCommand {
    /// Print the rules (TOML, the format `set` reads)
    Show {
        #[arg(short = 'g', long)]
        group: Option<String>,
    },
    /// Check a TOML file and make it the group's rules (admins only)
    Set {
        file: PathBuf,
        #[arg(short = 'g', long)]
        group: Option<String>,
    },
    /// Remove all rules: everybody may reach everybody (admins only)
    Clear {
        #[arg(short = 'g', long)]
        group: Option<String>,
    },
}

#[derive(Subcommand)]
enum NodeCommand {
    /// Members with their addresses, subnets and roles (from the group records)
    List {
        /// Group name or id (default: the only group)
        #[arg(short = 'g', long)]
        group: Option<String>,
    },
    /// Change a member (admins only): a new certificate, spread to everybody within seconds
    Set {
        /// Node key, a unique key prefix, or a member name
        #[arg(allow_hyphen_values = true)]
        node: String,
        /// Group name or id (default: the only group)
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// New name
        #[arg(short = 'n', long)]
        name: Option<String>,
        /// New IPv4 address in the group
        #[arg(short = 'a', long)]
        addr: Option<Ipv4Addr>,
        /// Add a subnet behind the node, or a public IPv6 /128 for it (repeatable)
        #[arg(long = "add-route", value_name = "PREFIX")]
        add_route: Vec<IpNet>,
        /// Remove a subnet or address (repeatable)
        #[arg(long = "del-route", value_name = "PREFIX")]
        del_route: Vec<IpNet>,
        /// Let the node relay for others
        #[arg(long, conflicts_with = "no_relay")]
        relay: bool,
        /// Stop the node relaying
        #[arg(long)]
        no_relay: bool,
    },
}

#[derive(Subcommand)]
enum DelegateCommand {
    /// Print a delegation for a member: it may then invite into its subnets (admins only)
    Add {
        /// Group name or id (default: the only group)
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// A name for the delegate
        name: String,
        /// A subnet of the group network it may give addresses in (repeatable)
        #[arg(long, required = true, value_name = "PREFIX")]
        scope: Vec<IpNet>,
        /// Days it is valid
        #[arg(long, default_value_t = 365, value_parser = clap::value_parser!(u64).range(1..=3650))]
        days: u64,
    },
    /// Take the right to invite back (admins only): its unused invites stop working, the members
    /// it brought in stay; a running node of this admin spreads it within seconds
    Remove {
        /// Group name or id (default: the only group)
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// Delegate's name or key
        name: String,
    },
    /// Delegates in force (admins), or this node's delegation
    List {
        /// Group name or id (default: the only group)
        #[arg(short = 'g', long)]
        group: Option<String>,
    },
    /// Make this node a delegate, with the text from `delegate add`
    Accept {
        // base64url may start with '-'
        #[arg(allow_hyphen_values = true)]
        text: String,
    },
}

#[derive(Subcommand)]
enum GroupCommand {
    /// Create a group; this node becomes its admin and first member
    Create {
        /// Local name of the group
        name: String,
        /// This node's address in the group (default: random in 10.10.33.0 with the [net] mask)
        #[arg(short = 'a', long)]
        addr: Option<Ipv4Addr>,
        /// This node's name in the group (default: start of its key)
        #[arg(short = 'n', long = "node-name")]
        node_name: Option<String>,
        /// A subnet behind this node, routed to it by every member (repeatable)
        #[arg(long = "route", value_name = "PREFIX")]
        routes: Vec<IpNet>,
        /// This node relays traffic between members that cannot reach each other directly
        #[arg(long)]
        relay: bool,
    },
    /// Print an invite for one new node (admins only)
    Invite {
        /// Group name or id (default: the only group)
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// Name of the new node
        #[arg(short = 'n', long, default_value = "member")]
        name: String,
        /// Address of the new node (default: random in the group network)
        #[arg(short = 'a', long)]
        addr: Option<Ipv4Addr>,
        /// Hours the invite can be used
        #[arg(long, default_value_t = JOIN_TTL_SECS / 3600)]
        ttl: u64,
        /// This node's fixed address (host:port, repeatable): the new node connects to it
        /// directly, with or without a tracker (set a fixed [peer] bind_port)
        #[arg(long = "static", value_name = "HOST:PORT")]
        statics: Vec<String>,
        /// A subnet behind the new node (its LAN for site-to-site) or a public IPv6 /128 for it,
        /// routed to it by every member (repeatable). Not for exits: members choose gateways
        /// themselves (`dvpn exit`)
        #[arg(long = "route", value_name = "PREFIX")]
        routes: Vec<IpNet>,
        /// The new node relays traffic between members that cannot reach each other directly
        /// (a node with a public address or a good connection)
        #[arg(long)]
        relay: bool,
    },
    /// Let a member invite into a part of the network, and take it back
    Delegate {
        #[command(subcommand)]
        cmd: DelegateCommand,
    },
    /// Join a group by invite (from the argument, a file or stdin)
    Join {
        // base64url may start with '-'
        #[arg(allow_hyphen_values = true)]
        invite: Option<String>,
        /// Read the invite from a file
        #[arg(short = 'i', long = "input")]
        inp: Option<PathBuf>,
    },
    /// List the groups of this node
    List,
    /// Members known from the group records (admins see everybody who joined)
    Members {
        /// Group name or id (default: the only group)
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// Also list revoked keys without a certificate (mostly the one-time keys of used invites)
        #[arg(short = 'a', long)]
        all: bool,
    },
    /// Exclude a node from the group (admins only) and change the group psk; a running node of
    /// this admin spreads it within seconds
    Revoke {
        /// Node key, a unique key prefix, or a member name (see `group members`)
        #[arg(allow_hyphen_values = true)]
        node: String,
        /// Group name or id (default: the only group)
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// Seconds until the new psk is used (members need to receive it first)
        #[arg(long = "in", default_value_t = 120)]
        lead: u64,
        /// Keep the group psk (the revoked node can then still unmask packet headers)
        #[arg(long)]
        no_rotate: bool,
    },
    /// Change the group psk (admins only), e.g. if it may have leaked
    Rotate {
        /// Group name or id (default: the only group)
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// Seconds until the new psk is used (members need to receive it first)
        #[arg(long = "in", default_value_t = 120)]
        lead: u64,
    },
    /// Save the group secret and admin material to a password-protected file (admins only)
    Backup {
        /// Group name or id (default: the only group)
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// Output file (default: print)
        #[arg(short = 'o', long = "output")]
        out: Option<PathBuf>,
    },
    /// Become the admin of a group from a backup (password from DVPN_BACKUP_PASSWORD or asked)
    Restore {
        /// Backup file (default: read from stdin)
        #[arg(short = 'i', long = "input")]
        inp: Option<PathBuf>,
        /// Also take over the backed-up node key: this node becomes that node
        #[arg(long)]
        with_key: bool,
    },
    /// Leave a group (removes it from config.toml)
    Leave {
        /// Group name or id
        group: String,
    },
}

fn die(msg: impl std::fmt::Display) -> ! {
    log::error!("{msg}");
    exit(1)
}

fn default_dir() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_else(|| PathBuf::from("."))
}

fn github_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut w: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<String>| {
        let cells: Vec<String> = cells.iter().enumerate().map(|(i, c)| format!(" {c:<0$} ", w[i])).collect();
        format!("|{}|", cells.join("|"))
    };
    let mut out = vec![line(headers.iter().map(|h| h.to_string()).collect())];
    out.push(format!("|{}|", w.iter().map(|n| "-".repeat(n + 2)).collect::<Vec<_>>().join("|")));
    out.extend(rows.iter().map(|r| line(r.clone())));
    out.join("\n")
}

fn pick_group<'a>(conf: &'a Config, group: &Option<String>) -> &'a GroupConfig {
    match group {
        Some(gr) => conf.group(gr).unwrap_or_else(|| die(format!("no group {gr}"))),
        None if conf.groups.len() == 1 => &conf.groups[0],
        None if conf.groups.is_empty() => die("not in any group"),
        None => die("give the group with --group"),
    }
}

/// The backup password: DVPN_BACKUP_PASSWORD, or asked on the terminal (twice when creating).
fn backup_password(new: bool) -> String {
    if let Ok(p) = std::env::var("DVPN_BACKUP_PASSWORD") {
        return p;
    }
    let p = rpassword::prompt_password("Backup password: ").unwrap_or_else(|e| die(format!("password: {e}")));
    if new {
        if p.chars().count() < 8 {
            die("use at least 8 characters");
        }
        let again = rpassword::prompt_password("Again: ").unwrap_or_else(|e| die(format!("password: {e}")));
        if again != p {
            die("the passwords differ");
        }
    }
    p
}

/// Every member's newest certificate in the records, plus our own from the config.
fn member_certs(conf: &Config, g: &GroupConfig, store: &StateStore) -> Vec<dvpn::group::Cert> {
    let mut v = store.certs(&g.id);
    if let Some(own) = &g.cert
        && !v.iter().any(|c| c.body.node == own.body.node && c.body.not_after >= own.body.not_after)
    {
        v.retain(|c| c.body.node != own.body.node);
        v.push(own.clone());
    }
    let _ = conf;
    v.sort_by(|a, b| a.body.name.cmp(&b.body.name));
    v
}

/// The running node's API address: `-a`, else the default socket of the config's TUN.
fn api_target(conf: &Config, cli_addr: Option<String>) -> String {
    if let Some(a) = cli_addr {
        return a;
    }
    #[cfg(unix)]
    for dir in api_socket_dirs() {
        let p = dir.join(format!("{}.sock", tun_name(conf)));
        if p.exists() {
            return p.display().to_string();
        }
    }
    let _ = conf;
    SOCKET_DEFAULT_ADDR.to_owned()
}

/// The name the API socket is named after: the TUN's, also without a TUN (`-d`, no `[net]`).
#[cfg(unix)]
fn tun_name(conf: &Config) -> &str {
    conf.net.as_ref().map_or("dnet", |n| n.tun_name.as_str())
}

/// Where the API's unix socket goes: `/run/dvpn` for a node of root or a service (group `dvpn`
/// may use it), else the user's own `$XDG_RUNTIME_DIR/dvpn`. UDP only without both, or by `-a`.
#[cfg(unix)]
fn api_socket_dirs() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from(config::SOCKET_DEFAULT_DIR)];
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
        v.push(PathBuf::from(d).join("dvpn"));
    }
    v
}

/// The running node's API (`--dir` / `-a`), or die.
fn api_client(rt: &tokio::runtime::Runtime, conf: &Config, cli_addr: Option<String>) -> dvpn_client::Client {
    let addr: dvpn_client::ApiAddr = api_target(conf, cli_addr).parse().unwrap_or_else(|e| match e {});
    rt.block_on(dvpn_client::Client::connect(addr.clone(), "dvpn-cli"))
        .unwrap_or_else(|e| die(format!("API {addr}: {e}")))
}

/// A request's answer, or die with the node's error.
fn ask<T>(rt: &tokio::runtime::Runtime, f: impl Future<Output = Result<T, dvpn_client::Error>>) -> T {
    rt.block_on(f).unwrap_or_else(|e| die(e))
}

fn dash(v: Option<impl std::fmt::Display>) -> String {
    v.map_or_else(|| "-".to_owned(), |v| v.to_string())
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// 1536 -> "1.5 KiB"
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let (mut v, mut u) = (n as f64, 0);
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

fn cmd_forward(conf: &Config, dir: &Path, cmd: ForwardCommand) {
    use dvpn::forward::{Forward, Proto};
    let proto_arg = |s: &str| Proto::parse(s).unwrap_or_else(|| die("--proto: tcp, udp or both"));
    let on = match &cmd {
        ForwardCommand::List { on } | ForwardCommand::Add { on, .. } | ForwardCommand::Del { on, .. } => on.clone(),
    };
    let store = StateStore::open(dir.join(STATE_FILE_NAME));
    let group = conf.groups.first();
    let certs = group.map_or_else(Vec::new, |g| member_certs(conf, g, &store));
    let me = conf.identity.id();
    // the gateway, unless it is this node
    let gateway = on.map(|s| ops::find_member(&certs, &s).unwrap_or_else(|e| die(e))).filter(|k| *k != me);
    let remote_of = |k: &dvpn::identity::NodeId| group.map_or_else(Vec::new, |g| store.forwards(&g.id, k));
    let local = || match config::read_forwards(conf.path()) {
        Ok(l) => l,
        Err(e) => die(format!("{e:#}")),
    };
    let mut rules = match gateway {
        Some(k) => remote_of(&k),
        None => local(),
    };
    match cmd {
        ForwardCommand::List { .. } => {
            let name = |to: &str| {
                certs.iter().find(|c| c.body.node.to_string() == to).map_or(to.to_owned(), |c| c.body.name.clone())
            };
            let row = |r: &Forward, from: &str| {
                vec![
                    r.proto.as_str().to_owned(),
                    r.port.to_string(),
                    format!("{}:{}", name(&r.to), r.to_port),
                    yes_no(r.keep_ip).to_owned(),
                    from.to_owned(),
                ]
            };
            let mut rows: Vec<Vec<String>> = Vec::new();
            match gateway {
                Some(_) => rows.extend(rules.iter().map(|r| row(r, "admin"))),
                None => {
                    rows.extend(rules.iter().map(|r| row(r, "config")));
                    let allowed = conf.gateway.as_ref().is_some_and(|g| g.allow_remote);
                    let from = if allowed { "admin" } else { "admin (not allowed here)" };
                    rows.extend(remote_of(&me).iter().map(|r| row(r, from)));
                }
            }
            println!("\n{}\n", github_table(&["Proto", "Port", "To", "Keeps IP", "From"], &rows));
            return;
        }
        ForwardCommand::Add { port, to, to_port, proto, keep_ip, .. } => {
            // this node's rules name members as the running node knows them, not all are on disk
            let proto = proto_arg(&proto);
            rules.push(Forward { proto, port, to, to_port: to_port.unwrap_or(port), keep_ip });
        }
        ForwardCommand::Del { port, proto, .. } => {
            let proto = proto_arg(&proto);
            let before = rules.len();
            rules.retain(|r| r.port != port || !r.proto.overlaps(proto));
            if rules.len() == before {
                die(format!("port {port} is not forwarded"));
            }
        }
    }
    dvpn::forward::check(&rules).unwrap_or_else(|e| die(e));
    match gateway {
        Some(k) => {
            let g = group.unwrap_or_else(|| die("this node is in no group"));
            let secret = ops::admin_secret(g).unwrap_or_else(|e| die(e));
            ops::set_forwards(secret, &store, &certs, k, rules).unwrap_or_else(|e| die(e));
            store.save();
            println!("A running node of this admin spreads it within seconds; the gateway needs allow_remote.");
        }
        None => {
            config::write_forwards(conf.path(), &rules).unwrap_or_else(|e| die(format!("{e:#}")));
            println!("A running node follows within seconds.");
        }
    }
}

fn cmd_acl(conf: &Config, dir: &Path, cmd: AclCommand) {
    let store = StateStore::open(dir.join(STATE_FILE_NAME));
    let group = match &cmd {
        AclCommand::Show { group } | AclCommand::Set { group, .. } | AclCommand::Clear { group } => group,
    };
    let g = pick_group(conf, group).clone();
    let certs = member_certs(conf, &g, &store);
    let name =
        |n: &NodeId| certs.iter().find(|c| c.body.node == *n).map_or_else(|| n.to_string(), |c| c.body.name.clone());
    match cmd {
        AclCommand::Show { .. } => match store.acl(&g.id) {
            Some(a) => print!("{}", a.to_toml(&name)),
            None => println!("# no rules: everybody may reach everybody\ndefault = \"allow\""),
        },
        AclCommand::Set { .. } | AclCommand::Clear { .. } if g.secret.is_none() => {
            die(format!("only admins of {} can set the rules", g.name))
        }
        AclCommand::Set { file, .. } => {
            let text = std::fs::read_to_string(&file).unwrap_or_else(|e| die(format!("read {}: {e}", file.display())));
            let secret = g.secret.as_ref().expect("checked");
            let (acl, _) =
                ops::set_acl(secret, &store, &certs, &text).unwrap_or_else(|e| die(format!("{}: {e}", file.display())));
            store.save();
            println!(
                "Rules of group {} set ({} rules, default {}):",
                g.name,
                acl.rules.len(),
                if acl.default_deny { "deny" } else { "allow" }
            );
            print!("{}", acl.to_toml(&name));
        }
        AclCommand::Clear { .. } => {
            let secret = g.secret.as_ref().expect("checked");
            ops::clear_acl(secret, &store).unwrap_or_else(|e| die(e));
            store.save();
            println!("Rules of group {} removed", g.name);
        }
    }
}

fn cmd_node(conf: &mut Config, dir: &Path, cmd: NodeCommand) {
    let store = StateStore::open(dir.join(STATE_FILE_NAME));
    match cmd {
        NodeCommand::List { group } => {
            let g = pick_group(conf, &group);
            let m = Membership::of(&store, &g.id);
            let rows: Vec<Vec<String>> = member_certs(conf, g, &store)
                .iter()
                .map(|c| {
                    let b = &c.body;
                    let mut roles = Vec::new();
                    for (bit, name) in [(dvpn::group::Roles::ADMIN, "admin"), (dvpn::group::Roles::RELAY, "relay")] {
                        if b.roles.has(bit) {
                            roles.push(name);
                        }
                    }
                    let addrs: Vec<String> = b
                        .prefixes
                        .iter()
                        .filter(|p| p.max_prefix_len() == p.prefix_len())
                        .map(|p| p.addr().to_string())
                        .collect();
                    let routes: Vec<String> = b
                        .prefixes
                        .iter()
                        .filter(|p| p.max_prefix_len() != p.prefix_len())
                        .map(|p| p.to_string())
                        .collect();
                    vec![
                        b.name.clone(),
                        b.node.short(),
                        addrs.join(", "),
                        routes.join(", "),
                        roles.join(","),
                        if m.revoked.contains(&b.node) {
                            "revoked".into()
                        } else {
                            format!("{} d", b.not_after.saturating_sub(now_unix()) / 86400)
                        },
                    ]
                })
                .collect();
            println!("\n{}\n", github_table(&["Name", "Key", "Addresses", "Routes", "Roles", "Cert valid"], &rows));
        }
        NodeCommand::Set { node, group, name, addr, add_route, del_route, relay, no_relay } => {
            let g = pick_group(conf, &group).clone();
            let secret = ops::admin_secret(&g).unwrap_or_else(|e| die(e));
            let certs = member_certs(conf, &g, &store);
            let key = ops::find_member(&certs, &node).unwrap_or_else(|e| die(e));
            let relay = if relay {
                Some(true)
            } else if no_relay {
                Some(false)
            } else {
                None
            };
            let change = ops::NodeChange { name, addr, add_routes: add_route, del_routes: del_route, relay };
            let (cert, _) = ops::change_node(secret, &store, &certs, key, &change).unwrap_or_else(|e| die(e));
            store.save();
            if key == conf.identity.id() {
                conf.set_group_cert(&g.id, &cert);
                conf.save();
            }
            let b = &cert.body;
            println!(
                "{} ({}): {}",
                b.name,
                b.node.short(),
                b.prefixes.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
            );
            println!("A running node of this admin spreads it within seconds; the member picks it up.");
        }
    }
}

fn cmd_group(conf: &mut Config, dir: &Path, cmd: GroupCommand) {
    let state = || StateStore::open(dir.join(STATE_FILE_NAME));
    let signs = matches!(
        cmd,
        GroupCommand::Create { .. }
            | GroupCommand::Invite { .. }
            | GroupCommand::Revoke { .. }
            | GroupCommand::Rotate { .. }
            | GroupCommand::Restore { .. }
            | GroupCommand::Delegate { cmd: DelegateCommand::Add { .. } | DelegateCommand::Remove { .. } }
    );
    if signs && !dvpn::clock::trusted() {
        die("the clock is earlier than this build: set it (NTP) before signing group records or certificates");
    }
    match cmd {
        GroupCommand::Create { name, addr, node_name, routes, relay } => {
            if conf.group(&name).is_some() {
                die(format!("group {name} already exists"));
            }
            if !conf.groups.is_empty() {
                die("this node is already in a group; several groups per node come later (PLAN stage 3.5)");
            }
            let prefix = ops::net_prefix(conf);
            let net = Ipv4Net::new(Ipv4Addr::new(10, 10, 33, 0), prefix).unwrap_or_else(|e| die(e)).trunc();
            let addr = addr.or_else(|| ops::free_host(net, &[], &[])).unwrap_or_else(|| die("no free address"));
            let id = conf.identity.id();
            let secret = GroupSecret::generate();
            let node_name = node_name.unwrap_or_else(|| id.short());
            let mut body = CertBody::new(id, &node_name, ops::host_net(addr, &routes));
            body.roles.0 = dvpn::group::Roles::ADMIN | if relay { dvpn::group::Roles::RELAY } else { 0 };
            let cert = secret.issue(body);
            let g = GroupConfig {
                name: name.clone(),
                id: secret.id(),
                psk: secret.psk(0),
                secret: Some(secret),
                epoch: 0,
                cert: Some(cert),
                obfs: Default::default(),
                obfs_entries: Vec::new(),
                delegate: None,
                delegations: Vec::new(),
            };
            println!("Group {name}: {}\nThis node: {node_name}, {addr}/{prefix}, admin", g.id);
            conf.add_group(g);
            conf.save();
            println!("The group secret is in config.toml ([[groups]] secret) and cannot be recovered if lost:");
            println!("back it up with: dvpn group backup -o <file>");
            println!("Invite nodes with: dvpn group invite --name <name>");
        }
        GroupCommand::Invite { group, name, addr, ttl, statics, routes, relay } => {
            let g = pick_group(conf, &group).clone();
            let store = state();
            let certs = member_certs(conf, &g, &store);
            let req = ops::InviteRequest { name, addr, ttl_hours: ttl, statics, routes, relay };
            let made = ops::invite(conf, &g, &certs, &store.revoked(&g.id), &req).unwrap_or_else(|e| die(e));
            for w in &made.warnings {
                log::warn!("{w}");
            }
            eprintln!("Invite for {} ({}) to {}, valid {ttl} h, for one node:", made.name, made.addr, g.name);
            println!("{}", made.invite);
        }
        GroupCommand::Delegate { cmd } => match cmd {
            DelegateCommand::Add { group, name, scope, days } => {
                let g = pick_group(conf, &group).clone();
                let (delegate, issued) = ops::add_delegate(conf, &g, &name, scope, days).unwrap_or_else(|e| die(e));
                let mut list = g.delegations.clone();
                list.push(issued);
                conf.set_group_delegations(&g.id, list);
                conf.save();
                eprintln!("Delegation for {name}, valid {days} d; on its node: dvpn group delegate accept <text>");
                println!("{}", delegate.encode());
            }
            DelegateCommand::Remove { group, name } => {
                let g = pick_group(conf, &group).clone();
                let secret = ops::admin_secret(&g).unwrap_or_else(|e| die(e));
                let store = state();
                let (d, _) = ops::remove_delegate(secret, &store, &g, &name).unwrap_or_else(|e| die(e));
                store.save();
                let list = g.delegations.iter().filter(|o| **o != d).cloned().collect();
                conf.set_group_delegations(&g.id, list);
                conf.save();
                println!("Delegate {} removed from group {}", d.name, g.name);
                println!("A running node of this admin spreads it to the trackers and members within seconds.");
            }
            DelegateCommand::List { group } => {
                let g = pick_group(conf, &group);
                let row = |name: &str, d: &dvpn::group::Delegation| {
                    let scope: Vec<String> = d.scope.iter().map(ToString::to_string).collect();
                    let days = d.until.saturating_sub(now_unix()) / 86400;
                    vec![name.to_owned(), d.key.to_string(), scope.join(", "), format!("{days} d")]
                };
                let mut rows: Vec<Vec<String>> = g.delegations.iter().map(|d| row(&d.name, &d.delegation)).collect();
                rows.extend(g.delegate.iter().map(|d| row("this node", &d.delegation)));
                println!("\n{}\n", github_table(&["Name", "Key", "Scope", "Valid"], &rows));
            }
            DelegateCommand::Accept { text } => {
                let d = ops::accept_delegate(conf, &text).unwrap_or_else(|e| die(format!("{e:#}")));
                let scope: Vec<String> = d.delegation.scope.iter().map(ToString::to_string).collect();
                println!("This node may invite into {}", scope.join(", "));
            }
        },
        GroupCommand::Join { invite, inp } => {
            let text = match (invite, inp) {
                (Some(t), _) => t,
                (None, Some(p)) => {
                    std::fs::read_to_string(&p).unwrap_or_else(|e| die(format!("read {}: {e}", p.display())))
                }
                (None, None) => {
                    print!("Paste invite: ");
                    let _ = std::io::stdout().flush();
                    let mut s = String::new();
                    let _ = std::io::stdin().lock().read_line(&mut s);
                    s
                }
            };
            let j = dvpn::ops::join(conf, &text).unwrap_or_else(|e| die(format!("{e:#}")));
            let addr = j.addr.map_or_else(|| "no address".into(), |a| a.to_string());
            println!("Joined group {} ({}) as {}, {addr}", j.group, j.id, j.name);
            if !j.added.is_empty() {
                println!("Added: {}", j.added.join(", "));
            }
        }
        GroupCommand::List => {
            let rows: Vec<Vec<String>> = conf
                .groups
                .iter()
                .map(|g| {
                    let cert = g.cert.as_ref();
                    vec![
                        g.name.clone(),
                        g.id.to_string(),
                        match (&g.secret, &g.delegate) {
                            (Some(_), _) => "admin".into(),
                            (None, Some(_)) => "delegate".into(),
                            (None, None) => "member".into(),
                        },
                        cert.map_or_else(String::new, |c| c.body.name.clone()),
                        g.ipv4().map_or_else(String::new, |a| a.to_string()),
                        cert.map_or_else(String::new, |c| {
                            let days = c.body.not_after.saturating_sub(now_unix()) / 86400;
                            if c.from_invite() { format!("{days} d (invite)") } else { format!("{days} d") }
                        }),
                    ]
                })
                .collect();
            println!("\n{}\n", github_table(&["Group", "Id", "Role", "Name", "Addr", "Cert valid"], &rows));
        }
        GroupCommand::Members { group, all } => {
            let g = pick_group(conf, &group);
            let store = state();
            let m = Membership::of(&store, &g.id);
            let mut certs = store.certs(&g.id);
            certs.sort_by(|a, b| a.body.name.cmp(&b.body.name));
            let mut rows: Vec<Vec<String>> = certs
                .iter()
                .map(|c| {
                    vec![
                        c.body.name.clone(),
                        c.body.node.to_string(),
                        c.body.ipv4().map_or_else(String::new, |a| a.to_string()),
                        if m.revoked.contains(&c.body.node) {
                            "revoked".into()
                        } else {
                            format!("{} d", c.body.not_after.saturating_sub(now_unix()) / 86400)
                        },
                    ]
                })
                .collect();
            // revoked keys nobody has a certificate of: mostly the one-time keys of used invites
            // (the admin revokes one when its member gets a regular certificate)
            let mut keys_only: Vec<String> =
                m.revoked.iter().filter(|r| !certs.iter().any(|c| c.body.node == **r)).map(|r| r.to_string()).collect();
            keys_only.sort();
            if all {
                rows.extend(keys_only.iter().map(|k| vec![String::new(), k.clone(), String::new(), "revoked".into()]));
            }
            if rows.is_empty() {
                println!("No records yet: members appear once an admin node has seen them online.");
            } else {
                println!("\n{}\n", github_table(&["Name", "Key", "Addr", "Cert valid"], &rows));
            }
            if !all && !keys_only.is_empty() {
                println!(
                    "{} revoked keys without a certificate (used invites) not shown; --all lists them.",
                    keys_only.len()
                );
            }
        }
        GroupCommand::Rotate { group, lead } => {
            let g = pick_group(conf, &group);
            let secret = ops::admin_secret(g).unwrap_or_else(|e| die(e));
            let store = state();
            let changed = ops::rotate(secret, &store, g.epoch, lead).unwrap_or_else(|e| die(e));
            store.save();
            println!(
                "psk epoch {} of group {} starts in {lead} s, sealed to {} members",
                ops::epoch_of(&changed).unwrap_or_default(),
                g.name,
                changed.len() - 1
            );
        }
        GroupCommand::Revoke { node, group, lead, no_rotate } => {
            let g = pick_group(conf, &group);
            let secret = ops::admin_secret(g).unwrap_or_else(|e| die(e));
            let store = state();
            let certs = store.certs(&g.id);
            let key = ops::find_member(&certs, &node).unwrap_or_else(|e| die(e));
            let rotate = (!no_rotate).then_some(lead);
            let changed =
                ops::revoke(secret, &store, conf.identity.id(), key, g.epoch, rotate).unwrap_or_else(|e| die(e));
            store.save();
            let name =
                certs.iter().find(|c| c.body.node == key).map_or_else(String::new, |c| format!(" ({})", c.body.name));
            println!("Revoked {key}{name} in group {}", g.name);
            if let Some(epoch) = ops::epoch_of(&changed) {
                println!("New group psk (epoch {epoch}) starts in {lead} s");
            }
            println!("A running node of this admin spreads it to the trackers and members within seconds.");
        }
        GroupCommand::Backup { group, out } => {
            let g = pick_group(conf, &group);
            let Some(secret) = &g.secret else { die(format!("only admins of {} have something to back up", g.name)) };
            let password = backup_password(true);
            let b = dvpn::backup::Backup {
                group_name: g.name.clone(),
                secret: *secret.as_bytes(),
                epoch: g.epoch,
                obfs: g.obfs_entries.clone(),
                trackers: conf.servers.iter().map(|s| s.tracker_ref()).collect(),
                statics: conf.static_peers.clone(),
                cert: g.cert.clone(),
                node_key: Some(conf.identity.private_key_text()),
            };
            let text = b.seal(&password, dvpn::backup::DEFAULT_COST);
            match out {
                Some(p) => {
                    std::fs::write(&p, text + "\n").unwrap_or_else(|e| die(format!("write {}: {e}", p.display())));
                    eprintln!("Backup of group {} written to {}", g.name, p.display());
                }
                None => println!("{text}"),
            }
            eprintln!("Keep it offline. With it and the password anybody can run the group.");
        }
        GroupCommand::Restore { inp, with_key } => {
            let text = match inp {
                Some(p) => std::fs::read_to_string(&p).unwrap_or_else(|e| die(format!("read {}: {e}", p.display()))),
                None => {
                    let mut s = String::new();
                    let _ = std::io::stdin().lock().read_line(&mut s);
                    s
                }
            };
            let b = dvpn::backup::Backup::open(&text, &backup_password(false)).unwrap_or_else(|e| die(e));
            let secret = GroupSecret::from_bytes(b.secret);
            if conf.groups.iter().any(|g| g.id == secret.id()) {
                die(format!("already in group {}", secret.id()));
            }
            if !conf.groups.is_empty() {
                die("this node is already in a group; several groups per node come later (PLAN stage 3.5)");
            }
            if with_key {
                let key = b.node_key.as_deref().unwrap_or_else(|| die("the backup has no node key"));
                conf.set_private_key(Identity::from_private_key_text(key).unwrap_or_else(|e| die(e)));
            }
            let me = conf.identity.id();
            let cert = match &b.cert {
                // the same node: its certificate goes on
                Some(c) if c.body.node == me && c.verify(&secret.id(), dvpn::clock::trusted_unix()).is_ok() => {
                    c.clone()
                }
                // another node takes over: same name, address and roles, for its own key
                Some(c) => {
                    let mut body = c.body.clone();
                    body.node = me;
                    body.not_after = now_unix() + dvpn::group::CERT_TTL_SECS;
                    body.serial = u64::from_le_bytes(random_bytes());
                    secret.issue(body)
                }
                None => {
                    let mut body = CertBody::new(me, &me.short(), Vec::new());
                    body.roles.0 = dvpn::group::Roles::ADMIN;
                    secret.issue(body)
                }
            };
            let obfs = parse_obfs(&b.obfs).unwrap_or_else(|e| die(format!("backup obfuscation profile: {e:#}")));
            for t in &b.trackers {
                conf.add_server(t);
            }
            for sp in &b.statics {
                conf.add_static_peer(sp);
            }
            let addr = cert.body.ipv4();
            conf.add_group(GroupConfig {
                name: b.group_name.clone(),
                id: secret.id(),
                psk: secret.psk(b.epoch),
                secret: Some(secret),
                epoch: b.epoch,
                cert: Some(cert),
                obfs,
                obfs_entries: b.obfs,
                delegate: None,
                delegations: Vec::new(),
            });
            conf.save();
            println!(
                "Restored group {} as admin, this node {}{}",
                b.group_name,
                me.short(),
                addr.map_or_else(String::new, |a| format!(", {a}"))
            );
            if !with_key && b.cert.as_ref().is_some_and(|c| c.body.node != me) {
                println!(
                    "This node has a new key; if the old admin node is lost for good, revoke it: dvpn group revoke <old key>"
                );
            }
        }
        GroupCommand::Leave { group } => {
            let admin = dvpn::ops::leave(conf, &group).unwrap_or_else(|e| die(format!("{e:#}")));
            if admin {
                log::warn!("Left a group this node administered: its secret is removed from config.toml");
            }
            println!("Left group {group}");
        }
    }
}

fn api_addr_default(conf: &Config) -> String {
    #[cfg(unix)]
    for dir in api_socket_dirs() {
        let shared = dir == Path::new(config::SOCKET_DEFAULT_DIR);
        let made = std::fs::create_dir_all(&dir).and_then(|()| {
            use std::os::unix::fs::PermissionsExt;
            // /run/dvpn must be passable for group dvpn; the user's own one is for the user alone
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(if shared { 0o755 } else { 0o700 }))
        });
        match made {
            Ok(()) => return dir.join(format!("{}.sock", tun_name(conf))).display().to_string(),
            Err(e) => log::debug!("API socket in {}: {e}", dir.display()),
        }
    }
    let _ = conf;
    log::info!("API on UDP {SOCKET_DEFAULT_ADDR}: changes need its token (see doc/api.md)");
    SOCKET_DEFAULT_ADDR.to_owned()
}

/// Ctrl+C, or SIGTERM (systemd, kill): both shut down cleanly (routes, tracker goodbye).
async fn wait_ctrl_c() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap_or_else(|e| die(format!("signal handler: {e}")));
        tokio::select! {
            _ = tokio::signal::ctrl_c() => log::info!(" Pressed Ctrl+C, exiting."),
            _ = term.recv() => log::info!("Terminated, exiting."),
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_close, ctrl_shutdown};
        let (Ok(mut close), Ok(mut shutdown), Ok(mut brk)) = (ctrl_close(), ctrl_shutdown(), ctrl_break()) else {
            let _ = tokio::signal::ctrl_c().await;
            return log::info!(" Pressed Ctrl+C, exiting.");
        };
        // closing the console window or the system shutting down: clean up as for Ctrl+C
        tokio::select! {
            _ = tokio::signal::ctrl_c() => log::info!(" Pressed Ctrl+C, exiting."),
            _ = brk.recv() => log::info!(" Pressed Ctrl+Break, exiting."),
            _ = close.recv() => log::info!("Console closed, exiting."),
            _ = shutdown.recv() => log::info!("System shutting down, exiting."),
        }
    }
}

/// Runs the node until `stop` (Ctrl+C, or the Windows service stopping).
async fn run_node(conf: Config, dir: PathBuf, api_addr: Option<String>, stop: impl std::future::Future<Output = ()>) {
    let api_addr = api_addr.unwrap_or_else(|| api_addr_default(&conf));
    let opts = dvpn::run::Options { api_addr, tun: dvpn::run::Tun::FromConfig, protect: None, on_plan: None };
    let running = dvpn::run::start(conf, &dir, opts).await.unwrap_or_else(|e| die(format!("{e:#}")));
    stop.await;
    running.shutdown().await;
}

async fn run_server(conf: &mut Config, addr: std::net::IpAddr, port: u16) {
    let key = match conf.local_server_key {
        Some(k) => SigningKey::from_bytes(&k),
        None => SigningKey::from_bytes(&random_bytes()),
    };
    let public = key.verifying_key().to_bytes();
    if conf.local_server_key.is_none() || conf.local_server_public_key().as_deref() != Some(&public[..]) {
        conf.set_local_server(&key.to_bytes(), &public);
        conf.save();
    }
    log::info!("Public key: {}", encode_b64(&public));
    tokio::select! {
        r = tracker_server::run(addr, port, Identity::from_seed(&key.to_bytes())) => {
            if let Err(e) = r {
                die(format!("Socket bind error: {e}"));
            }
        }
        _ = wait_ctrl_c() => {}
    }
    log::info!("Server stopped");
}

fn main() {
    let cli = Cli::parse();
    if cli.version {
        println!("Version: {VERSION} | Author: {AUTHOR}\n");
        println!("Если вам скучно или нужна помощь: {EMAIL}");
        println!("+{}+", "-".repeat(47));
        println!("If you are bored or need help: {EMAIL}\n");
        return;
    }
    match &cli.command {
        Some(Command::GenKey) => return println!("{}", Identity::generate().private_key_text()),
        Some(Command::ShowKey { key: Some(k) }) => {
            let id = Identity::from_private_key_text(k).unwrap_or_else(|e| {
                eprintln!("Invalid private key: {e}");
                exit(1)
            });
            return println!("{}", id.id());
        }
        _ => {}
    }

    logger::init(LevelFilter::Info);
    let dir = cli.dir.clone().unwrap_or_else(default_dir);
    let mut conf = Config::load(&dir).unwrap_or_else(|e| die(format!("Error, {e:#}")));
    logger::set_level(conf.log_level);
    if cli.disable_net {
        conf.net = None;
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| die(format!("runtime: {e}")));

    match cli.command {
        None => {
            log::info!("Starting dvpn {VERSION}");
            log::info!("Node key: {}", conf.identity.id());
            rt.block_on(run_node(conf, dir, cli.api_addr, wait_ctrl_c()));
        }
        Some(Command::GenKey | Command::ShowKey { key: Some(_) }) => unreachable!(),
        Some(Command::ShowKey { key: None }) => println!("{}", conf.identity.id()),
        Some(Command::Group(cmd)) => cmd_group(&mut conf, &dir, cmd),
        Some(Command::Node(cmd)) => cmd_node(&mut conf, &dir, cmd),
        Some(Command::Acl(cmd)) => cmd_acl(&conf, &dir, cmd),
        Some(Command::Forward(cmd)) => cmd_forward(&conf, &dir, cmd),
        Some(Command::Status) => {
            let c = api_client(&rt, &conf, cli.api_addr);
            let s = ask(&rt, c.status());
            println!("node      {} ({})", s.name, s.key);
            println!("group     {} ({}){}", s.group_name, s.group, if s.admin { ", admin" } else { "" });
            println!("addresses {}, {}", s.prefixes.join(", "), s.ula);
            println!("relay     {}   certificate valid {} more days", yes_no(s.relay), s.cert_days);
            println!("socket    {}", dash(s.local_addr));
            for t in &s.servers {
                println!("tracker   {} {}", t.addr, if t.connected { "connected" } else { "not connected" });
            }
            println!(
                "exit      IPv4 {}, IPv6 {}{}",
                dash(s.exit_v4),
                dash(s.exit_v6),
                if s.kill_switch { "  (kill switch on: no gateway alive)" } else { "" }
            );
        }
        Some(Command::Neighbors) => {
            let c = api_client(&rt, &conf, cli.api_addr);
            let rows: Vec<Vec<String>> = ask(&rt, c.neighbors())
                .into_iter()
                .map(|n| {
                    vec![
                        dash(n.name),
                        n.key.chars().take(10).collect(),
                        dash(n.endpoint),
                        dash(n.rtt_ms.map(|r| format!("{r:.1}"))),
                        yes_no(n.alive).into(),
                        format!("{} s", n.session_secs),
                        human_bytes(n.tx_bytes),
                        human_bytes(n.rx_bytes),
                    ]
                })
                .collect();
            println!(
                "\n{}\n",
                github_table(&["Name", "Key", "Endpoint", "RTT ms", "Alive", "Session", "Sent", "Received"], &rows)
            );
        }
        Some(Command::Routes) => {
            let c = api_client(&rt, &conf, cli.api_addr);
            let r = ask(&rt, c.routes());
            let mesh: Vec<Vec<String>> = r
                .mesh
                .into_iter()
                .map(|m| vec![dash(m.name), m.key.chars().take(10).collect(), dash(m.via_name), m.cost.to_string()])
                .collect();
            println!("\nMesh (node: first hop, cost in ms)\n{}", github_table(&["Node", "Key", "Via", "Cost"], &mesh));
            let ckr: Vec<Vec<String>> = r.ckr.into_iter().map(|c| vec![c.net, c.to, yes_no(c.system).into()]).collect();
            println!("\nCKR (destination: node)\n{}\n", github_table(&["Prefix", "To", "System route"], &ckr));
        }
        Some(Command::Metrics) => {
            let c = api_client(&rt, &conf, cli.api_addr);
            let m = ask(&rt, c.metrics());
            let pair = |p: dvpn_client::Counter| format!("{} / {}", p.packets, human_bytes(p.bytes));
            let rows: Vec<Vec<String>> = m
                .peers
                .into_iter()
                .map(|p| {
                    vec![
                        dash(p.name),
                        p.key.chars().take(10).collect(),
                        pair(p.ip_tx),
                        pair(p.ip_rx),
                        pair(p.wire_tx),
                        pair(p.wire_rx),
                    ]
                })
                .collect();
            println!(
                "\nUptime {} s, handshakes {}, relayed for others {}",
                m.uptime_secs,
                m.handshakes,
                pair(m.relayed)
            );
            println!(
                "\nTraffic (packets / bytes; IP: with the member on any path, wire: the direct session)\n{}",
                github_table(&["Name", "Key", "IP sent", "IP received", "Wire sent", "Wire received"], &rows)
            );
            let drops: Vec<Vec<String>> = m.drops.into_iter().map(|(k, n)| vec![k, n.to_string()]).collect();
            println!("\nDropped packets\n{}\n", github_table(&["Reason", "Packets"], &drops));
        }
        Some(Command::Ping { node, count }) => {
            let c = api_client(&rt, &conf, cli.api_addr);
            let (mut got, mut sum) = (0, 0.0);
            for i in 0..count {
                if i > 0 {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                match ask(&rt, c.ping(&node)) {
                    None => println!("{node}: no answer"),
                    Some(p) => {
                        let via = match p.via {
                            dvpn_client::Via::Direct => "direct",
                            dvpn_client::Via::Relays => "relays",
                        };
                        println!("{node}: {:.2} ms ({via})", p.rtt_ms);
                        got += 1;
                        sum += p.rtt_ms;
                    }
                }
            }
            println!(
                "{got} of {count} answered{}",
                if got > 0 { format!(", average {:.2} ms", sum / f64::from(got)) } else { String::new() }
            );
            if got == 0 {
                exit(1);
            }
        }
        Some(Command::Path { node }) => {
            let c = api_client(&rt, &conf, cli.api_addr);
            match ask(&rt, c.path(&node)) {
                Some(hops) if !hops.is_empty() => {
                    let names: Vec<String> = hops.into_iter().map(|h| h.name.unwrap_or(h.key)).collect();
                    println!("{} (this node) -> {}", conf.identity.id().short(), names.join(" -> "));
                }
                _ => die(format!("no route to {node}")),
            }
        }
        Some(Command::Exit { v4, v6, none, kill_switch, dns, sources, table, only }) => {
            let mut e = conf.exits.clone();
            if none {
                e = config::Exits::default();
            }
            if let Some(v) = v4 {
                e.v4 = v.into_iter().filter(|s| !s.is_empty()).collect();
            }
            if let Some(v) = v6 {
                e.v6 = v.into_iter().filter(|s| !s.is_empty()).collect();
            }
            if let Some(k) = kill_switch {
                e.kill_switch = Some(k == "on");
            }
            if let Some(d) = dns {
                e.dns = d
                    .iter()
                    .filter(|s| !s.is_empty() && *s != "none")
                    .map(|s| s.parse().unwrap_or_else(|_| die(format!("--dns {s}: not an IP address"))))
                    .collect();
            }
            if let Some(list) = sources {
                (e.v4_sources, e.v6_sources) = (Vec::new(), Vec::new());
                for s in list.iter().filter(|s| !s.is_empty() && *s != "none") {
                    let net = s
                        .parse::<ipnet::IpNet>()
                        .or_else(|_| s.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                        .unwrap_or_else(|_| die(format!("--sources {s}: not a network")));
                    match net {
                        ipnet::IpNet::V4(n) => e.v4_sources.push(n),
                        ipnet::IpNet::V6(n) => e.v6_sources.push(n),
                    }
                }
            }
            if let Some(t) = table {
                e.table = if t == "none" {
                    None
                } else {
                    let n = t.parse().unwrap_or_else(|_| die(format!("--table {t}: a number or none")));
                    Some(config::check_table(n).unwrap_or_else(|err| die(format!("--{err}"))))
                };
            }
            if let Some(f) = only {
                e.only_file = if f.as_os_str() == "none" {
                    None
                } else {
                    // the node may run from another directory (a service): keep the full path
                    let f =
                        std::fs::canonicalize(&f).unwrap_or_else(|err| die(format!("--only {}: {err}", f.display())));
                    config::read_only_list(&f).unwrap_or_else(|err| die(format!("--only {err:#}")));
                    Some(f)
                };
            }
            if e != conf.exits {
                conf.set_exits(&e);
                conf.save();
            }
            let show = |l: &[String]| if l.is_empty() { "none".to_owned() } else { l.join(" > ") };
            println!("IPv4 exit: {}\nIPv6 exit: {}", show(&e.v4), show(&e.v6));
            if !e.v4.is_empty() || !e.v6.is_empty() {
                println!("kill switch: {}", if e.kill_switch() { "on (no gateway: no internet)" } else { "off" });
            }
            if e.split() {
                let src = e.sources();
                let table = e.table.unwrap_or(dvpn::sysroute::EXIT_TABLE);
                if src.is_empty() {
                    println!("only what your rules send to table {table} (DVPN adds no rule)");
                } else {
                    let s: Vec<String> = src.iter().map(|n| n.to_string()).collect();
                    println!("only from {} (table {table}); this node itself goes direct", s.join(", "));
                }
            }
            if let Some(f) = &e.only_file {
                match config::read_only_list(f) {
                    Ok(l) => println!(
                        "only to the {} destinations in {}; the rest of the internet goes direct",
                        l.len(),
                        f.display()
                    ),
                    Err(err) => println!("only to the destinations in {}: cannot read it now ({err:#})", f.display()),
                }
            }
            if !e.dns.is_empty() {
                println!(
                    "DNS through the gateway: {}",
                    e.dns.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ")
                );
            }
        }
        Some(Command::Server { addr, port }) => rt.block_on(run_server(&mut conf, addr, port)),
        #[cfg(windows)]
        Some(Command::Service(cmd)) => cmd_service(cmd, conf, dir, cli.api_addr, rt),
    }
}

#[cfg(windows)]
fn cmd_service(cmd: ServiceCommand, conf: Config, dir: PathBuf, api_addr: Option<String>, rt: tokio::runtime::Runtime) {
    use windows_service::service::ServiceState;
    let fail = |what: &str, e: windows_service::Error| -> ! {
        die(format!("service {what}: {e} (run it from an Administrator prompt)"))
    };
    match cmd {
        ServiceCommand::Run => {
            winservice::log_to_file(&dir);
            log::info!("Starting dvpn {VERSION} as the Windows service");
            log::info!("Node key: {}", conf.identity.id());
            let body: winservice::Body = Box::new(move |stop| {
                rt.block_on(run_node(conf, dir, api_addr, async {
                    let _ = stop.await;
                    log::info!("Service stopping");
                }))
            });
            if let Err(e) = winservice::dispatch(body) {
                die(format!(
                    "not started by the service manager ({e}): use `dvpn service install`, or run without `service`"
                ));
            }
        }
        ServiceCommand::Install => {
            let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
            // canonicalize gives \\?\C:\...; the service manager wants the plain path
            let plain = PathBuf::from(dir.to_string_lossy().trim_start_matches(r"\\?\").to_owned());
            winservice::install(&plain).unwrap_or_else(|e| fail("install", e));
            println!(
                "Service {} installed for {} and started; log: {}",
                winservice::NAME,
                plain.display(),
                plain.join("dvpn.log").display()
            );
        }
        ServiceCommand::Uninstall => {
            winservice::uninstall().unwrap_or_else(|e| fail("uninstall", e));
            println!("Service {} stopped and removed", winservice::NAME);
        }
        ServiceCommand::Start => match winservice::start() {
            Ok(true) => println!("Service started"),
            Ok(false) => println!("Service starting (see dvpn.log)"),
            Err(e) => fail("start", e),
        },
        ServiceCommand::Stop => match winservice::stop() {
            Ok(true) => println!("Service stopped"),
            Ok(false) => println!("Service stopping"),
            Err(e) => fail("stop", e),
        },
        ServiceCommand::Status => match winservice::state() {
            Ok(None) => println!("Service not installed"),
            Ok(Some(ServiceState::Running)) => println!("Service running"),
            Ok(Some(ServiceState::Stopped)) => println!("Service stopped"),
            Ok(Some(s)) => println!("Service {s:?}"),
            Err(e) => fail("status", e),
        },
    }
}
