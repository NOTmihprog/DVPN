mod api;
mod config;
mod crypto;
mod logger;
mod node;
mod packet;
mod peer_id;
mod proto;
mod storage;
mod tracker_client;
mod tracker_server;
mod transport;

use std::io::{BufRead, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use log::LevelFilter;
use serde_json::Value as Json;

use crate::config::{Config, PEERS_FILE_NAME, SOCKET_DEFAULT_ADDR};
use crate::crypto::{decode_b64, encode_b64, generate_key, random_bytes};
use crate::peer_id::{PEER_ID_LEN, PeerId};
use crate::storage::{PeerRecord, PeerStorage, PeerUpdate, normalize_key};
use crate::tracker_client::TrackerClient;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHOR: &str = "mihprog";
const EMAIL: &str = "mih@mihprog.com";

#[derive(Parser)]
#[command(name = "dvpn", disable_version_flag = true, about = "Decentralized P2P VPN")]
struct Cli {
    /// Directory with config.toml and peers.json (default: executable directory)
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

#[derive(Args)]
struct OutputArgs {
    /// Do not encode json to base64
    #[arg(short = 'j', long = "json")]
    json: bool,
    /// Output file path
    #[arg(short = 'o', long = "output")]
    out: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate new peer-id
    GenPeerId,
    /// Generate new symmetric encryption key
    GenKey,
    /// Set or add peer or peer parameters
    Set {
        /// Peer_id: len 32, alphanumeric, generate: gen-peer-id (a unique prefix of a known id is enough)
        #[arg(short = 'p', long)]
        peer_id: String,
        /// Peer name, "None" to clear
        #[arg(short = 'n', long)]
        name: Option<String>,
        /// IPv4 address in the LAN network, "None" to clear
        #[arg(short = 'a', long)]
        addr: Option<String>,
        /// Crypto key, 32 bytes in base64, generate: gen-key, "None" to clear
        #[arg(short = 'k', long)]
        key: Option<String>,
        /// Clear parameters that are not given
        #[arg(short = 'c', long)]
        clear: bool,
        /// Use this peer id and its LAN address as self
        #[arg(short = 's', long = "self")]
        set_self: bool,
    },
    /// Delete peer by id
    Del {
        #[arg(short = 'p', long)]
        peer_id: String,
    },
    /// Show peers table
    List,
    /// Export peers to base64 or json
    Export(OutputArgs),
    /// Import peers from base64 or json
    Import {
        /// Input file path (default: read from stdin)
        #[arg(short = 'i', long = "input")]
        inp: Option<PathBuf>,
        /// Delete current peers first
        #[arg(short = 'c', long = "clear")]
        clear: bool,
    },
    /// Export one peer to base64 or json
    ExportPeer {
        /// Peer_id, default: self
        #[arg(short = 'p', long)]
        peer_id: Option<String>,
        #[command(flatten)]
        out: OutputArgs,
    },
    /// Import one peer from base64 or json
    ImportPeer {
        #[arg(short = 'i', long = "input")]
        inp: Option<PathBuf>,
    },
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

fn die(msg: impl std::fmt::Display) -> ! {
    log::error!("{msg}");
    exit(1)
}

fn default_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn resolve_peer_id(s: &str, storage: &PeerStorage) -> PeerId {
    if s.len() < PEER_ID_LEN {
        storage.find(s).unwrap_or_else(|| die(format!("Peer_id {s} not found")))
    } else {
        s.parse().unwrap_or_else(|e| die(format!("Peer_id {s} invalid: {e}")))
    }
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

fn list_peers(storage: &PeerStorage) {
    let self_id = storage.self_id();
    let rows: Vec<Vec<String>> = storage
        .list()
        .into_iter()
        .map(|(r, _)| {
            let name = r.name.clone().unwrap_or_else(|| "None".into());
            vec![
                if r.peer_id == self_id { format!("[{name}]") } else { name },
                r.peer_id.to_string(),
                r.addr.map_or_else(|| "None".into(), |a| a.to_string()),
                r.key.map_or_else(|| "disabled".into(), |k| format!("key: {k}")),
            ]
        })
        .collect();
    println!("\n{}\n", github_table(&["Name", "PeerID", "Addr", "encryption"], &rows));
}

fn export_value(r: &PeerRecord) -> Json {
    serde_json::json!({ "name": r.name, "peer_id": r.peer_id, "addr": r.addr, "key": r.key })
}

fn write_output(args: &OutputArgs, data: &Json) {
    let mut text = data.to_string();
    if !args.json {
        text = encode_b64(text.as_bytes());
    }
    match &args.out {
        None => println!("{text}"),
        Some(p) => std::fs::write(p, text).unwrap_or_else(|e| die(format!("Write file error: {e}"))),
    }
}

fn read_input(inp: &Option<PathBuf>) -> Json {
    let text = match inp {
        Some(p) => std::fs::read_to_string(p).unwrap_or_else(|e| die(format!("Open file error: {e}"))),
        None => {
            print!("Paste peers string: ");
            let _ = std::io::stdout().flush();
            let mut s = String::new();
            let _ = std::io::stdin().lock().read_line(&mut s);
            s
        }
    };
    let text = text.trim();
    let decoded = decode_b64(text).ok().and_then(|b| String::from_utf8(b).ok());
    serde_json::from_str(decoded.as_deref().unwrap_or(text)).unwrap_or_else(|_| die("Load error"))
}

/// Accepts the v3 export format and v2 exports (`crypto: {key}`, `id`).
fn parse_import(mut v: Json) -> anyhow::Result<PeerRecord> {
    if let Some(obj) = v.as_object_mut() {
        if !obj.contains_key("key")
            && let Some(k) = obj.get("crypto").and_then(|c| c.get("key")).cloned() {
                obj.insert("key".into(), k);
            }
        obj.remove("crypto");
    }
    let mut r: PeerRecord = serde_json::from_value(v)?;
    r.key = r.key.as_deref().map(normalize_key).transpose().context("key")?;
    Ok(r)
}

fn store_import(storage: &PeerStorage, r: PeerRecord) {
    storage.set_peer(
        r.peer_id,
        PeerUpdate {
            name: Some(r.name),
            addr: Some(r.addr),
            key: Some(r.key),
            endpoint: None,
            sub_args: r.sub_args.map(Some),
        },
    );
}

/// `None` = not given, `Some(None)` = "None" literal (clear), `Some(Some(v))` = set.
fn cli_field(v: Option<String>) -> Option<Option<String>> {
    v.map(|s| if s == "None" || s.is_empty() { None } else { Some(s) })
}

#[allow(clippy::too_many_arguments)]
fn cmd_set(
    conf: &mut Config,
    storage: &PeerStorage,
    peer_id: String,
    name: Option<String>,
    addr: Option<String>,
    key: Option<String>,
    clear: bool,
    set_self: bool,
) {
    let id = resolve_peer_id(&peer_id, storage);
    let addr = cli_field(addr).map(|a| {
        a.map(|s| s.parse::<Ipv4Addr>().unwrap_or_else(|e| die(format!("addr invalid, error: {e}"))))
    });
    let key = cli_field(key).map(|k| k.map(|s| normalize_key(&s).unwrap_or_else(|e| die(format!("key {s} invalid: {e}")))));
    let name = cli_field(name);
    fn pick<T>(f: Option<Option<T>>, clear: bool) -> Option<Option<T>> {
        if clear { Some(f.flatten()) } else { f }
    }
    storage.set_peer(
        id,
        PeerUpdate {
            name: pick(name, clear),
            addr: pick(addr, clear),
            key: pick(key, clear),
            endpoint: None,
            sub_args: None,
        },
    );

    if set_self {
        conf.set_peer_id(id);
        if let Some(a) = storage.get(&id).and_then(|(r, _)| r.addr) {
            conf.set_net_addr(a);
        }
        conf.save();
        storage.set_self_id(id);
    }
    list_peers(storage);
}

fn api_addr_default(conf: &Config) -> String {
    #[cfg(unix)]
    if let Some(net) = &conf.net {
        let dir = Path::new(config::SOCKET_DEFAULT_DIR);
        match std::fs::create_dir_all(dir) {
            Ok(()) => return dir.join(format!("{}.sock", net.tun_name)).display().to_string(),
            Err(e) => log::info!("Failed create directory: {}: {e}, use net socket: {SOCKET_DEFAULT_ADDR}", dir.display()),
        }
    }
    let _ = conf;
    SOCKET_DEFAULT_ADDR.to_owned()
}

fn build_tun(net: &config::NetConfig) -> anyhow::Result<tun_rs::AsyncDevice> {
    let dev = tun_rs::DeviceBuilder::new()
        .name(&net.tun_name)
        .ipv4(net.addr, net.prefix, None)
        .mtu(net.mtu)
        .build_async()?;
    Ok(dev)
}

async fn wait_ctrl_c() {
    let _ = tokio::signal::ctrl_c().await;
    log::info!(" Pressed Ctrl+C, exiting.");
}

async fn run_node(conf: Config, storage: Arc<PeerStorage>, api_addr: Option<String>) {
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

    let tun = conf.net.as_ref().map(|net| match build_tun(net) {
        Ok(dev) => {
            log::info!("TUN | {} {}/{} mtu {} - started", net.tun_name, net.addr, net.prefix, net.mtu);
            dev
        }
        Err(e) => die(format!("TUN | Tun init error: {e}")),
    });

    let clients = conf
        .servers
        .iter()
        .map(|s| TrackerClient::new(s.name.clone(), s.addr, s.key))
        .collect();
    let node = node::Node::new(storage, transport, clients, tun, conf.net.as_ref().map(|n| n.addr));
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
        Some(Command::GenPeerId) => return println!("{}", PeerId::generate()),
        Some(Command::GenKey) => return println!("{}", generate_key()),
        _ => {}
    }

    logger::init(LevelFilter::Info);
    let dir = cli.dir.clone().unwrap_or_else(default_dir);
    let mut conf = Config::load(&dir).unwrap_or_else(|e| die(format!("Error, {e:#}")));
    logger::set_level(conf.log_level);
    if cli.disable_net {
        conf.net = None;
    }

    let storage = PeerStorage::load(conf.peer.peer_id, Some(dir.join(PEERS_FILE_NAME)))
        .unwrap_or_else(|e| die(format!("Error, {e:#}")));
    let self_id = storage.self_id();

    // peers.json is the source of truth for the own LAN address once it is set.
    if let Some(net_addr) = conf.net.as_ref().map(|n| n.addr) {
        match storage.get(&self_id).and_then(|(r, _)| r.addr) {
            None => storage.set_peer(self_id, PeerUpdate { addr: Some(Some(net_addr)), ..Default::default() }),
            Some(a) if a != net_addr => {
                conf.set_net_addr(a);
                conf.save();
            }
            Some(_) => {}
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| die(format!("runtime: {e}")));

    match cli.command {
        None => {
            log::info!("Starting dvpn {VERSION}");
            rt.block_on(run_node(conf, Arc::new(storage), cli.api_addr));
        }
        Some(Command::GenPeerId | Command::GenKey) => unreachable!(),
        Some(Command::Set { peer_id, name, addr, key, clear, set_self }) => {
            cmd_set(&mut conf, &storage, peer_id, name, addr, key, clear, set_self)
        }
        Some(Command::Del { peer_id }) => {
            let id = resolve_peer_id(&peer_id, &storage);
            if storage.is_self(&id) {
                die("error delete self peer");
            }
            storage.del_peer(&id);
            list_peers(&storage);
        }
        Some(Command::List) => list_peers(&storage),
        Some(Command::Export(out)) => {
            let peers: Vec<Json> = storage.list().iter().map(|(r, _)| export_value(r)).collect();
            write_output(&out, &Json::Array(peers));
        }
        Some(Command::Import { inp, clear }) => {
            let Json::Array(items) = read_input(&inp) else { die("data is not a list") };
            if clear {
                for id in storage.ids() {
                    if !storage.is_self(&id) {
                        storage.del_peer(&id);
                    }
                }
            }
            for item in items {
                match parse_import(item) {
                    Ok(r) => store_import(&storage, r),
                    Err(e) => log::warn!("Skip peer: {e:#}"),
                }
            }
            list_peers(&storage);
        }
        Some(Command::ExportPeer { peer_id, out }) => {
            let id = peer_id.map_or(self_id, |p| resolve_peer_id(&p, &storage));
            let (r, _) = storage.get(&id).unwrap_or_else(|| die(format!("Peer_id {id} not found")));
            write_output(&out, &export_value(&r));
        }
        Some(Command::ImportPeer { inp }) => {
            let v = read_input(&inp);
            if !v.is_object() {
                die("data is not an object");
            }
            match parse_import(v) {
                Ok(r) => store_import(&storage, r),
                Err(e) => die(format!("Peer load error: {e:#}")),
            }
            list_peers(&storage);
        }
        Some(Command::Server { addr, port }) => rt.block_on(run_server(&mut conf, addr, port)),
    }
}
