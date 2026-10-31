use std::io::Write;
use std::sync::{Arc, OnceLock};

use log::{Level, LevelFilter, Log, Metadata, Record};

use crate::identity::{NODE_ID_TEXT_LEN, NodeId};
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

/// From now on peer ids in log messages are shown together with the peer name.
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

impl Logger {
    fn decorate(&self, msg: String) -> String {
        let Some(storage) = self.storage.get() else { return msg };
        let b = msg.as_bytes();
        let mut out = String::with_capacity(msg.len() + 32);
        let mut i = 0;
        let mut last = 0;
        // Stopgap until log call sites format ids themselves (stage 1.5): any 43-char base64url
        // token that parses as a node key and is known to the storage gets its name attached.
        let is_b64 = |c: &u8| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_';
        while i + NODE_ID_TEXT_LEN <= b.len() {
            let boundary_before = i == 0 || !is_b64(&b[i - 1]);
            let boundary_after = b.get(i + NODE_ID_TEXT_LEN).is_none_or(|c| !is_b64(c));
            let token = &b[i..i + NODE_ID_TEXT_LEN];
            let id = (boundary_before && boundary_after && token.iter().all(is_b64))
                .then(|| msg[i..i + NODE_ID_TEXT_LEN].parse::<NodeId>().ok())
                .flatten()
                .filter(|id| storage.exists(id));
            if let Some(id) = id {
                let name = storage.name(&id).unwrap_or_else(|| "None".into());
                out.push_str(&msg[last..i]);
                out.push_str(&format!("{YELLOW}{name}{DARK_GREEN}({GREY}{id}{DARK_GREEN}){WHITE}"));
                i += NODE_ID_TEXT_LEN;
                last = i;
            } else {
                i += 1;
            }
        }
        out.push_str(&msg[last..]);
        out
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
        let msg = self.decorate(r.args().to_string());
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
