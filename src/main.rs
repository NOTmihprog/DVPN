use std::io::{BufRead, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use ipnet::{IpNet, Ipv4Net};
use log::LevelFilter;

use dvpn::{api, config, logger, node, tracker_server, transport};

use dvpn::config::{Config, GroupConfig, SOCKET_DEFAULT_ADDR, STATE_FILE_NAME, parse_obfs};
use dvpn::crypto::{encode_b64, random_bytes};
use dvpn::group::{CertBody, GroupSecret, Invite, JOIN_TTL_SECS, now_unix};
use dvpn::identity::{Identity, NodeId};
use dvpn::state::{Body, Membership, StateStore};
use dvpn::storage::{PeerStorage, PeerUpdate};
use dvpn::tracker_client::TrackerClient;

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
    /// Start peer discovery server
    Server {
        /// Server bind ipv4 addr
        #[arg(short = 'a', long, default_value = "0.0.0.0")]
        addr: Ipv4Addr,
        /// Server bind port
        #[arg(short = 'p', long, default_value_t = 6485)]
        port: u16,
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

fn net_prefix(conf: &Config) -> u8 {
    conf.net.as_ref().map_or(24, |n| n.prefix)
}

/// A random host of `net` that is none of `taken`.
fn free_host(net: Ipv4Net, taken: &[Ipv4Addr]) -> Ipv4Addr {
    loop {
        let a = config::random_host(net.network(), net.prefix_len());
        if !taken.contains(&a) {
            return a;
        }
    }
}

fn host_net(addr: Ipv4Addr) -> Vec<IpNet> {
    vec![IpNet::V4(Ipv4Net::new(addr, 32).expect("/32 is valid"))]
}

fn pick_group<'a>(conf: &'a Config, group: &Option<String>) -> &'a GroupConfig {
    match group {
        Some(gr) => conf.group(gr).unwrap_or_else(|| die(format!("no group {gr}"))),
        None if conf.groups.len() == 1 => &conf.groups[0],
        None if conf.groups.is_empty() => die("not in any group"),
        None => die("give the group with --group"),
    }
}

fn epoch_of(changed: &[dvpn::state::Entry]) -> u32 {
    changed
        .iter()
        .find_map(|e| match e.body {
            Body::Epoch { epoch, .. } => Some(epoch),
            _ => None,
        })
        .unwrap_or_default()
}

fn cmd_group(conf: &mut Config, dir: &Path, cmd: GroupCommand) {
    let state = || StateStore::open(dir.join(STATE_FILE_NAME));
    match cmd {
        GroupCommand::Create { name, addr, node_name } => {
            if conf.group(&name).is_some() {
                die(format!("group {name} already exists"));
            }
            if !conf.groups.is_empty() {
                die("this node is already in a group; several groups per node come later (PLAN stage 3.5)");
            }
            let prefix = net_prefix(conf);
            let net = Ipv4Net::new(Ipv4Addr::new(10, 10, 33, 0), prefix).unwrap_or_else(|e| die(e)).trunc();
            let addr = addr.unwrap_or_else(|| free_host(net, &[]));
            let id = conf.identity.id();
            let secret = GroupSecret::generate();
            let node_name = node_name.unwrap_or_else(|| id.short());
            let mut body = CertBody::new(id, &node_name, host_net(addr));
            body.roles.0 = dvpn::group::Roles::ADMIN;
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
            };
            println!("Group {name}: {}\nThis node: {node_name}, {addr}/{prefix}, admin", g.id);
            conf.add_group(g);
            conf.save();
            println!("The group secret is in config.toml ([[groups]] secret): back it up, it cannot be recovered.");
            println!("Invite nodes with: dvpn group invite --name <name>");
        }
        GroupCommand::Invite { group, name, addr, ttl } => {
            let g = pick_group(conf, &group);
            let Some(secret) = &g.secret else { die(format!("only admins of {} can invite", g.name)) };
            let own = g.ipv4().unwrap_or_else(|| die("this node has no address in the group"));
            let net = Ipv4Net::new(own, net_prefix(conf)).unwrap_or_else(|e| die(e)).trunc();
            let addr = addr.unwrap_or_else(|| free_host(net, &[own]));
            if conf.servers.is_empty() {
                log::warn!("No [servers] configured: the invite has no tracker, the new node will not find anybody");
            }
            let template = CertBody::new(conf.identity.id(), &name, host_net(addr));
            let join = secret.grant_join(template, now_unix() + ttl * 3600);
            let trackers = conf.servers.iter().map(|s| s.tracker_ref()).collect();
            let inv = Invite::new(&g.name, g.epoch, g.psk, g.obfs_entries.clone(), trackers, join);
            eprintln!("Invite for {name} ({addr}) to {}, valid {ttl} h, for one node:", g.name);
            println!("{}", inv.encode());
        }
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
            let inv = Invite::decode(&text, Some(now_unix())).unwrap_or_else(|e| die(e));
            if conf.groups.iter().any(|g| g.id == inv.group()) {
                die(format!("already in group {}", inv.group()));
            }
            if !conf.groups.is_empty() {
                die("this node is already in a group; several groups per node come later (PLAN stage 3.5)");
            }
            let obfs = parse_obfs(&inv.obfs).unwrap_or_else(|e| die(format!("invite obfuscation profile: {e:#}")));
            let cert = inv.join.enroll(conf.identity.id());
            let body = cert.body.clone();
            let mut name = inv.name.clone();
            while conf.group(&name).is_some() {
                name.push('_');
            }
            let added: Vec<String> =
                inv.trackers.iter().filter(|t| conf.add_server(t)).map(|t| format!("{}:{}", t.host, t.port)).collect();
            conf.add_group(GroupConfig {
                name: name.clone(),
                id: inv.group(),
                secret: None,
                epoch: inv.epoch,
                psk: inv.psk,
                cert: Some(cert),
                obfs,
                obfs_entries: inv.obfs.clone(),
            });
            conf.save();
            let addr = body.ipv4().map_or_else(|| "no address".into(), |a| a.to_string());
            println!("Joined group {name} ({}) as {}, {addr}", inv.group(), body.name);
            if !added.is_empty() {
                println!("Added servers: {}", added.join(", "));
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
                        if g.secret.is_some() { "admin".into() } else { "member".into() },
                        cert.map_or_else(String::new, |c| c.body.name.clone()),
                        g.ipv4().map_or_else(String::new, |a| a.to_string()),
                        cert.map_or_else(String::new, |c| {
                            let days = c.body.not_after.saturating_sub(now_unix()) / 86400;
                            if c.grant.is_some() { format!("{days} d (invite)") } else { format!("{days} d") }
                        }),
                    ]
                })
                .collect();
            println!("\n{}\n", github_table(&["Group", "Id", "Role", "Name", "Addr", "Cert valid"], &rows));
        }
        GroupCommand::Members { group } => {
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
            for r in &m.revoked {
                if !certs.iter().any(|c| c.body.node == *r) {
                    rows.push(vec![String::new(), r.to_string(), String::new(), "revoked".into()]);
                }
            }
            println!("\n{}\n", github_table(&["Name", "Key", "Addr", "Cert valid"], &rows));
            if rows.is_empty() {
                println!("No records yet: members appear once an admin node has seen them online.");
            }
        }
        GroupCommand::Rotate { group, lead } => {
            let g = pick_group(conf, &group);
            let Some(secret) = &g.secret else { die(format!("only admins of {} can change the psk", g.name)) };
            let store = state();
            let changed = store.rotate(secret, g.epoch, lead * 1000);
            store.save();
            println!(
                "psk epoch {} of group {} starts in {lead} s, sealed to {} members",
                epoch_of(&changed),
                g.name,
                changed.len() - 1
            );
        }
        GroupCommand::Revoke { node, group, lead, no_rotate } => {
            let g = pick_group(conf, &group);
            let Some(secret) = &g.secret else { die(format!("only admins of {} can revoke", g.name)) };
            let store = state();
            let certs = store.certs(&g.id);
            let key: NodeId = match node.parse() {
                Ok(k) => k,
                Err(_) => {
                    let hits: Vec<NodeId> = certs
                        .iter()
                        .filter(|c| c.body.name == node || c.body.node.to_string().starts_with(&node))
                        .map(|c| c.body.node)
                        .collect();
                    match hits.as_slice() {
                        [k] => *k,
                        [] => die(format!("{node}: no such member key, key prefix or name (see dvpn group members)")),
                        _ => die(format!("{node} matches {} members, give the key", hits.len())),
                    }
                }
            };
            if key == conf.identity.id() {
                die("an admin cannot revoke itself; leave the group instead");
            }
            store.add(secret, Body::Revoke { key }, false);
            let name =
                certs.iter().find(|c| c.body.node == key).map_or_else(String::new, |c| format!(" ({})", c.body.name));
            println!("Revoked {key}{name} in group {}", g.name);
            if !no_rotate {
                let changed = store.rotate(secret, g.epoch, lead * 1000);
                println!("New group psk (epoch {}) starts in {lead} s", epoch_of(&changed));
            }
            store.save();
            println!("A running node of this admin spreads it to the trackers and members within seconds.");
        }
        GroupCommand::Leave { group } => {
            let id = conf.group(&group).unwrap_or_else(|| die(format!("no group {group}"))).id;
            if conf.groups.iter().any(|g| g.id == id && g.secret.is_some()) {
                log::warn!("Leaving a group this node administers: its secret is removed from config.toml");
            }
            conf.remove_group(&id);
            conf.save();
            println!("Left group {group}");
        }
    }
}

fn api_addr_default(conf: &Config) -> String {
    #[cfg(unix)]
    if let Some(net) = &conf.net {
        let dir = Path::new(config::SOCKET_DEFAULT_DIR);
        match std::fs::create_dir_all(dir) {
            Ok(()) => return dir.join(format!("{}.sock", net.tun_name)).display().to_string(),
            Err(e) => {
                log::info!("Failed create directory: {}: {e}, use net socket: {SOCKET_DEFAULT_ADDR}", dir.display())
            }
        }
    }
    let _ = conf;
    SOCKET_DEFAULT_ADDR.to_owned()
}

fn build_tun(net: &config::NetConfig, addr: Ipv4Addr) -> anyhow::Result<tun_rs::AsyncDevice> {
    let dev =
        tun_rs::DeviceBuilder::new().name(&net.tun_name).ipv4(addr, net.prefix, None).mtu(net.mtu).build_async()?;
    Ok(dev)
}

async fn wait_ctrl_c() {
    let _ = tokio::signal::ctrl_c().await;
    log::info!(" Pressed Ctrl+C, exiting.");
}

async fn run_node(mut conf: Config, dir: PathBuf, api_addr: Option<String>) {
    let group = match conf.groups.as_slice() {
        [] => die("not in any group: create one (dvpn group create) or join one (dvpn group join)"),
        [g] => g.clone(),
        _ => die("several groups per node come later (PLAN stage 3.5): leave all but one"),
    };
    let Some(mut cert) = group.cert.clone() else { die(format!("no certificate for group {}", group.name)) };
    let store = Arc::new(StateStore::open(dir.join(STATE_FILE_NAME)));
    // a renewed certificate may have arrived while the config was not updated
    if let Some(c) = store.cert(&group.id, &conf.identity.id())
        && c.body.not_after > cert.body.not_after
    {
        conf.set_group_cert(&group.id, &c);
        conf.save();
        cert = c;
    }
    if let Err(e) = cert.verify(&group.id, Some(now_unix())) {
        die(format!("own certificate in group {}: {e}; ask an admin for a new invite", group.name));
    }
    let self_addr = cert.body.ipv4();
    let storage = Arc::new(PeerStorage::new(conf.identity.id()));
    storage.set_peer(conf.identity.id(), PeerUpdate::from_cert(&cert));

    let api_addr = api_addr.unwrap_or_else(|| api_addr_default(&conf));
    let api_sock = api::ApiSocket::bind(&api_addr)
        .await
        .unwrap_or_else(|e| die(format!("Failed start api on address {api_addr}: {e}")));

    logger::attach_storage(storage.clone());
    if conf.net.is_none() {
        log::info!("Network disabled");
    }
    if conf.servers.is_empty() {
        log::warn!("No [servers] configured, peers can only be reached via endpoints set through the API");
    }

    let transport = transport::Transport::new(conf.peer.bind_addr, conf.peer.port_range)
        .await
        .unwrap_or_else(|e| die(format!("Peer socket bind error: {e}")));
    if let Ok(a) = transport.local_addr() {
        log::info!("Peer | Listen address: {a}");
    }

    let tun = conf.net.as_ref().map(|net| {
        let addr = self_addr.unwrap_or_else(|| die("the group certificate has no IPv4 address for the TUN interface"));
        match build_tun(net, addr) {
            Ok(dev) => {
                log::info!("TUN | {} {addr}/{} mtu {} - started", net.tun_name, net.prefix, net.mtu);
                dev
            }
            Err(e) => die(format!("TUN | Tun init error: {e}")),
        }
    });

    log::info!("Group {} ({}) as {}", group.name, group.id.short(), cert.body.name);
    let identity = Arc::new(conf.identity.clone());
    let links = dvpn::link::Links::new(
        identity.clone(),
        dvpn::link::Group { id: group.id, psk: group.psk, obfs: group.obfs.clone(), cert: cert.clone() },
    );
    let clients = conf
        .servers
        .iter()
        .map(|s| TrackerClient::new(s.name.clone(), s.addr, s.key, identity.clone(), vec![cert.clone()], store.clone()))
        .collect();
    let group_id = group.id;
    let dir2 = dir.clone();
    let ctx = node::GroupCtx {
        id: group.id,
        secret: group.secret.clone(),
        cert: cert.clone(),
        store,
        epoch: group.epoch,
        psk: group.psk,
        identity: identity.clone(),
        on_cert: Box::new(move |c| match Config::load(&dir) {
            Ok(mut conf) => {
                conf.set_group_cert(&group_id, c);
                conf.save();
            }
            Err(e) => log::warn!("Config | renewed certificate not saved: {e:#}"),
        }),
        on_epoch: Box::new(move |epoch, psk| match Config::load(&dir2) {
            Ok(mut conf) => {
                conf.set_group_epoch(&group_id, epoch, &psk);
                conf.save();
            }
            Err(e) => log::warn!("Config | new psk epoch not saved: {e:#}"),
        }),
    };
    let node = node::Node::new(storage.clone(), transport, links, clients, tun, self_addr, ctx);
    node.start();
    let _api = api::Api::start(node.clone(), api_sock);

    wait_ctrl_c().await;
    node.shutdown().await;
}

async fn run_server(conf: &mut Config, addr: Ipv4Addr, port: u16) {
    let key = match conf.local_server_key {
        Some(k) => SigningKey::from_bytes(&k),
        None => SigningKey::from_bytes(&random_bytes()),
    };
    let public = key.verifying_key().to_bytes();
    if conf.local_server_key.is_none() || conf.local_server_public_key().as_deref() != Some(&public[..]) {
        conf.set_local_server(&key.to_bytes(), &public);
        conf.save();
    }
    let sock = tokio::net::UdpSocket::bind(SocketAddrV4::new(addr, port))
        .await
        .unwrap_or_else(|e| die(format!("Socket bind error: {e}")));
    log::info!("Public key: {}", encode_b64(&public));
    log::info!("Server started listen: {addr}:{port}");
    tokio::select! {
        _ = tracker_server::run(sock, key) => {}
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
            rt.block_on(run_node(conf, dir, cli.api_addr));
        }
        Some(Command::GenKey | Command::ShowKey { key: Some(_) }) => unreachable!(),
        Some(Command::ShowKey { key: None }) => println!("{}", conf.identity.id()),
        Some(Command::Group(cmd)) => cmd_group(&mut conf, &dir, cmd),
        Some(Command::Server { addr, port }) => rt.block_on(run_server(&mut conf, addr, port)),
    }
}
