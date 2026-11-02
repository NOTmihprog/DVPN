use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rmpv::Value;
use serde::de::DeserializeOwned;
use tokio::sync::{Mutex, broadcast, oneshot};

use crate::transport::Socket;
use crate::types::*;
use crate::wire::{decode, encode, field, field_str, from_value, map};
use crate::{API_VERSION, ApiAddr, Error, ErrorCode};

/// How long a request waits for its answer (`ping` waits up to 2 s for the member).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

type Reply = Result<Value, Error>;

struct Shared {
    sock: Socket,
    name: String,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    /// The answer to our `init`, while we wait for it.
    init: Mutex<Option<oneshot::Sender<Reply>>>,
    events: broadcast::Sender<Value>,
}

impl Shared {
    fn init_msg(&self) -> Vec<u8> {
        encode(&map(vec![
            ("type", "init".into()),
            ("name", self.name.as_str().into()),
            ("version", API_VERSION.into()),
        ]))
    }
}

/// A connection to a node's API. Answers the node's pings and introduces itself again when the
/// node forgets it (`close`), so it can be kept for as long as the program runs.
pub struct Client {
    shared: Arc<Shared>,
    next_id: AtomicU64,
    timeout: Duration,
    info: InitInfo,
    task: tokio::task::JoinHandle<()>,
}

impl Client {
    /// Connects to the node at `addr` as `name` (shown in the node's log).
    pub async fn connect(addr: ApiAddr, name: &str) -> Result<Client, Error> {
        let sock = Socket::open(&addr).await?;
        let (events, _) = broadcast::channel(256);
        let shared =
            Arc::new(Shared { sock, name: name.to_owned(), pending: Mutex::default(), init: Mutex::default(), events });
        let task = tokio::spawn(recv_loop(shared.clone()));
        let (tx, rx) = oneshot::channel();
        *shared.init.lock().await = Some(tx);
        shared.sock.send(&shared.init_msg()).await?;
        let answer = match tokio::time::timeout(DEFAULT_TIMEOUT, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(Error::Closed),
            Err(_) => Err(Error::Timeout),
        };
        let info = match answer.and_then(from_value::<InitInfo>) {
            Ok(i) => i,
            Err(e) => {
                task.abort();
                return Err(e);
            }
        };
        Ok(Client { shared, next_id: AtomicU64::new(1), timeout: DEFAULT_TIMEOUT, info, task })
    }

    /// How long requests wait for their answers.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// The node, as it answered `init`.
    pub fn info(&self) -> &InitInfo {
        &self.info
    }

    /// Everything the node sends besides answers (`event`, `net`), as it comes. Typed events
    /// come later (PLAN stage 3).
    pub fn raw_events(&self) -> broadcast::Receiver<Value> {
        self.shared.events.subscribe()
    }

    /// Any request: `{"type": kind, "req": req, ...fields}`; its `res`, or the node's error.
    pub async fn raw(&self, kind: &str, req: &str, fields: Vec<(&str, Value)>) -> Result<Value, Error> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut m = vec![("type", Value::from(kind)), ("id", Value::from(id)), ("req", Value::from(req))];
        m.extend(fields);
        let (tx, rx) = oneshot::channel();
        self.shared.pending.lock().await.insert(id, tx);
        if let Err(e) = self.shared.sock.send(&encode(&map(m))).await {
            self.shared.pending.lock().await.remove(&id);
            return Err(e.into());
        }
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(Error::Closed),
            Err(_) => {
                self.shared.pending.lock().await.remove(&id);
                Err(Error::Timeout)
            }
        }
    }

    async fn get<T: DeserializeOwned>(&self, req: &str, fields: Vec<(&str, Value)>) -> Result<T, Error> {
        from_value(self.raw("get", req, fields).await?)
    }

    pub async fn status(&self) -> Result<Status, Error> {
        self.get("status", Vec::new()).await
    }

    pub async fn version(&self) -> Result<Version, Error> {
        self.get("version", Vec::new()).await
    }

    pub async fn neighbors(&self) -> Result<Vec<Neighbor>, Error> {
        self.get("neighbors", Vec::new()).await
    }

    pub async fn routes(&self) -> Result<Routes, Error> {
        self.get("routes", Vec::new()).await
    }

    pub async fn metrics(&self) -> Result<Metrics, Error> {
        self.get("metrics", Vec::new()).await
    }

    /// The hops to `node` (a key, key prefix or member name); None: no path now.
    pub async fn path(&self, node: &str) -> Result<Option<Vec<Hop>>, Error> {
        self.get("path", vec![("key", node.into())]).await
    }

    /// The round trip to `node` over our session with it; None: no answer within 2 s.
    pub async fn ping(&self, node: &str) -> Result<Option<Ping>, Error> {
        self.get("ping", vec![("key", node.into())]).await
    }

    pub async fn group(&self) -> Result<Group, Error> {
        self.get("group", Vec::new()).await
    }

    /// Everybody in the group, offline and revoked ones included, by name.
    pub async fn members(&self) -> Result<Vec<Member>, Error> {
        self.get("members", Vec::new()).await
    }

    pub async fn exit(&self) -> Result<Exit, Error> {
        self.get("exit", Vec::new()).await
    }

    /// Changes `[exit]` (like `dvpn exit`); answers the new state.
    pub async fn set_exit(&self, u: &ExitUpdate) -> Result<Exit, Error> {
        let list = |l: &Vec<String>| Value::Array(l.iter().map(|s| Value::from(s.as_str())).collect());
        let mut f = Vec::new();
        if u.clear {
            f.push(("clear", Value::from(true)));
        }
        if let Some(l) = &u.v4 {
            f.push(("v4", list(l)));
        }
        if let Some(l) = &u.v6 {
            f.push(("v6", list(l)));
        }
        if let Some(k) = u.kill_switch {
            f.push(("kill_switch", k.map_or(Value::Nil, Value::from)));
        }
        if let Some(l) = &u.dns {
            f.push(("dns", list(l)));
        }
        if let Some(l) = &u.sources {
            f.push(("sources", list(l)));
        }
        if let Some(t) = u.table {
            f.push(("table", t.map_or(Value::Nil, Value::from)));
        }
        from_value(self.raw("set", "exit", f).await?)
    }

    pub async fn acl(&self) -> Result<Acl, Error> {
        self.get("acl", Vec::new()).await
    }

    /// Drops the current connection to `node`: it is made again from scratch.
    pub async fn reset_endpoint(&self, node: &str) -> Result<(), Error> {
        self.raw("del", "peer_endpoint", vec![("key", node.into())]).await.map(|_| ())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.shared.sock.try_send(&encode(&map(vec![("type", "close".into())])));
        self.task.abort();
    }
}

async fn recv_loop(shared: Arc<Shared>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match shared.sock.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                // UDP: the node is not there (ICMP port unreachable); answers time out
                log::debug!("dvpn-client | recv: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let Some(v) = decode(&buf[..n]) else { continue };
        match field_str(&v, "type") {
            Some("res") => {
                let Some(id) = field(&v, "id").and_then(Value::as_u64) else { continue };
                let Some(tx) = shared.pending.lock().await.remove(&id) else { continue };
                let reply = match field_str(&v, "err") {
                    Some(code) => Err(Error::Api {
                        code: ErrorCode::from(code),
                        msg: field_str(&v, "msg").unwrap_or_default().to_owned(),
                    }),
                    None => Ok(field(&v, "res").cloned().unwrap_or(Value::Nil)),
                };
                let _ = tx.send(reply);
            }
            Some("init") => {
                if let Some(tx) = shared.init.lock().await.take() {
                    let _ = tx.send(Ok(v));
                }
            }
            Some("error") => {
                let code = field_str(&v, "err").unwrap_or_default();
                let msg = field_str(&v, "msg").unwrap_or_default().to_owned();
                if code == ErrorCode::VersionUnsupported.as_str() {
                    let num = |k| field(&v, k).and_then(Value::as_u64).unwrap_or_default();
                    if let Some(tx) = shared.init.lock().await.take() {
                        let _ = tx.send(Err(Error::VersionUnsupported { min: num("min"), max: num("max"), msg }));
                        continue;
                    }
                }
                log::warn!("dvpn-client | node: {msg} ({code})");
            }
            Some("ping") => {
                let _ = shared.sock.send(&encode(&map(vec![("type", "pong".into())]))).await;
            }
            Some("close") => {
                // the node forgot us (restarted, or we missed its pings): introduce ourselves again
                log::debug!("dvpn-client | the node closed the connection, init again");
                let _ = shared.sock.send(&shared.init_msg()).await;
            }
            _ => {
                let _ = shared.events.send(v);
            }
        }
    }
}
