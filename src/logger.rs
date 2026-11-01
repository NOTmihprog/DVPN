use std::fmt;
use std::io::Write;
use std::sync::{Arc, OnceLock};

use log::{Level, LevelFilter, Log, Metadata, Record};

use crate::identity::NodeId;
use crate::storage::PeerStorage;

const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[92m";
const CYAN_DIM: &str = "\x1b[2;36m";
const YELLOW: &str = "\x1b[93m";
const WHITE: &str = "\x1b[97m";
const GREY: &str = "\x1b[90m";
const DARK_GREEN: &str = "\x1b[32m";

struct Logger {
    storage: OnceLock<Arc<PeerStorage>>,
}

static LOGGER: Logger = Logger { storage: OnceLock::new() };

pub fn init(level: LevelFilter) {
    #[cfg(windows)]
    let _ = enable_ansi_support::enable_ansi_support();
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(level);
}

pub fn set_level(level: LevelFilter) {
    log::set_max_level(level);
}

/// From now on `node(id)` in log messages shows the node name too.
pub fn attach_storage(storage: Arc<PeerStorage>) {
    let _ = LOGGER.storage.set(storage);
}

fn level_name(l: Level) -> &'static str {
    match l {
        Level::Error => "ERROR",
        Level::Warn => "WARNING",
        Level::Info => "INFO",
        Level::Debug => "DEBUG",
        Level::Trace => "TRACE",
    }
}

/// Shows a node id in a log message as `name(prefix)`, or just the prefix when the node has no
/// name or no storage is attached (tracker server). `{:#}` prints the full key instead of the
/// prefix. Usage: `log::info!("Peer {} new endpoint {addr}", logger::node(id))`.
pub fn node(id: NodeId) -> Node {
    Node(id)
}

pub struct Node(NodeId);

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key = if f.alternate() { self.0.to_string() } else { self.0.short() };
        // Never block here: storage methods log while holding the storage lock.
        match LOGGER.storage.get().and_then(|s| s.name_if_unlocked(&self.0)) {
            Some(name) => write!(f, "{YELLOW}{name}{DARK_GREEN}({GREY}{key}{DARK_GREEN}){WHITE}"),
            None => write!(f, "{GREY}{key}{WHITE}"),
        }
    }
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        m.level() <= log::max_level()
    }

    fn log(&self, r: &Record) {
        if !self.enabled(r.metadata()) || !r.target().starts_with("dvpn") {
            return;
        }
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S,%3f");
        let msg = r.args();
        let mut out = std::io::stderr().lock();
        let _ = writeln!(
            out,
            "{GREEN}|{CYAN_DIM}{ts}{RESET}{GREEN}|{RESET} {} {GREEN}|{YELLOW}->{RESET} {WHITE}{msg}{RESET}",
            level_name(r.level())
        );
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::PeerUpdate;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn plain(s: String) -> String {
        let mut out = String::new();
        let mut it = s.chars();
        while let Some(c) = it.next() {
            if c == '\x1b' {
                it.by_ref().find(|c| *c == 'm');
            } else {
                out.push(c);
            }
        }
        out
    }

    // The only test that attaches a storage: LOGGER is process-global.
    #[test]
    fn node_display_and_no_deadlock_under_storage_lock() {
        let s = Arc::new(PeerStorage::new(NodeId::random()));
        let (a, b) = (NodeId::random(), NodeId::random());
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        s.set_peer(a, PeerUpdate { name: Some(Some("alice".into())), addr: Some(Some(ip)), ..Default::default() });

        assert_eq!(plain(node(a).to_string()), a.short(), "no storage attached yet");
        init(LevelFilter::Warn);
        attach_storage(s.clone());
        assert_eq!(plain(node(a).to_string()), format!("alice({})", a.short()));
        assert_eq!(plain(format!("{:#}", node(a))), format!("alice({a})"));
        assert_eq!(plain(node(b).to_string()), b.short(), "unknown node: prefix only");

        // Storage logs these while holding its write lock; formatting must not wait for it.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            s.set_peer(b, PeerUpdate { addr: Some(Some(ip)), ..Default::default() }); // shared addr
            tx.send(()).unwrap();
        });
        rx.recv_timeout(Duration::from_secs(10)).expect("logging under the storage lock deadlocked");
    }
}
