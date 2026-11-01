//! Group records (PLAN §8.1), the stage 3 subset: revocations and certificates issued by admins.
//!
//! Every record is signed by the group key, so any node and any tracker can check it knowing only
//! the group id, and nobody without the group secret can forge one. Records replicate by
//! last-writer-wins on `ts` (milliseconds; ties broken by the payload bytes), through trackers and
//! directly between nodes (`SyncMsg`), and nodes keep them in `state.bin` so revocations survive
//! restarts. Stage 6 adds node info and settings to the same store.
//!
//! ```text
//! revoke/<key>     Revoke { key }    certificates of `key`, or made with join key `key`, are invalid
//! cert/<node>      Cert(cert)        a certificate an admin issued or renewed for `node`
//! epoch            Epoch             psk epoch `epoch` is used from `active_from` on (PLAN §4.4, §5.2)
//! epochkey/<node>  EpochKey          that epoch's psk, sealed to `node`'s key
//! ```
//!
//! The psk of a new epoch is sealed to each member separately (X25519 with the node key), so a
//! revoked node, which gets no sealed copy, cannot read it although every record is public.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use blake2::{Blake2s256, Digest};
use ed25519_dalek::Signature;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::group::{Cert, GroupId, GroupSecret};
use crate::identity::{Identity, NodeId};

pub type RecordKey = [u8; 16];

/// Records from further in the future are refused (a wrong clock must not win every LWW race).
pub const MAX_CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;
pub const MAX_RECORD_LEN: usize = 1024;
/// Per group, so a member cannot fill a tracker's memory.
pub const MAX_GROUP_RECORDS: usize = 4096;
const RECORD_CTX: &[u8] = b"dvpn/4 record\0";
/// Datagram budget for the records of one sync message.
const RECORDS_BUDGET: usize = 1100;
const SUMMARY_CHUNK: usize = 40;

pub use crate::clock::now_ms;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body {
    Revoke {
        key: NodeId,
    },
    Cert(Box<Cert>),
    /// Unix milliseconds.
    Epoch {
        epoch: u32,
        active_from: u64,
    },
    EpochKey {
        node: NodeId,
        epoch: u32,
        eph: [u8; 32],
        sealed: Vec<u8>,
    },
}

impl Body {
    fn id(&self) -> String {
        match self {
            Body::Revoke { key } => format!("revoke/{key}"),
            Body::Cert(c) => format!("cert/{}", c.body.node),
            Body::Epoch { .. } => "epoch".into(),
            Body::EpochKey { node, .. } => format!("epochkey/{node}"),
        }
    }
}

fn epoch_seal_key(
    group: &GroupId,
    node: &NodeId,
    epoch: u32,
    eph: &[u8; 32],
    shared: &[u8; 32],
) -> chacha20poly1305::Key {
    let mut k = [0u8; 32];
    let info: [&[u8]; 5] = [b"dvpn/4 epoch psk", group.as_bytes(), node.as_bytes(), &epoch.to_le_bytes(), eph];
    hkdf::Hkdf::<sha2::Sha256>::new(None, shared).expand_multi_info(&info, &mut k).expect("32 bytes");
    k.into()
}

/// The psk of `epoch` sealed to `node` (an `EpochKey` body).
pub fn seal_psk(group: &GroupId, node: &NodeId, epoch: u32, psk: &[u8; 32]) -> Body {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    let secret = x25519_dalek::StaticSecret::from(crate::crypto::random_bytes::<32>());
    let eph = x25519_dalek::PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&node.x25519_public());
    let key = epoch_seal_key(group, node, epoch, &eph, shared.as_bytes());
    // the key is used once (fresh ephemeral), so a zero nonce is fine
    let sealed = ChaCha20Poly1305::new(&key).encrypt(&Default::default(), &psk[..]).expect("encrypt");
    Body::EpochKey { node: *node, epoch, eph, sealed }
}

fn open_psk(group: &GroupId, identity: &Identity, epoch: u32, eph: &[u8; 32], sealed: &[u8]) -> Option<[u8; 32]> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    let shared = identity.x25519_secret().diffie_hellman(&x25519_dalek::PublicKey::from(*eph));
    let key = epoch_seal_key(group, &identity.id(), epoch, eph, shared.as_bytes());
    ChaCha20Poly1305::new(&key).decrypt(&Default::default(), sealed).ok()?.try_into().ok()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub group: GroupId,
    pub id: String,
    pub ts: u64,
    /// A tombstone: the record with this id no longer applies.
    pub deleted: bool,
    pub body: Body,
}

/// A signed entry; the signature covers the exact payload bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub payload: Vec<u8>,
    pub sig: Signature,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecordError {
    TooLarge,
    Encoding,
    BadSignature,
    /// The id does not match the body, or a certificate is for another group.
    Inconsistent,
    FromTheFuture,
    Full,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RecordError::TooLarge => "record too large",
            RecordError::Encoding => "record encoding",
            RecordError::BadSignature => "bad record signature",
            RecordError::Inconsistent => "inconsistent record",
            RecordError::FromTheFuture => "record from the future",
            RecordError::Full => "too many records in the group",
        })
    }
}

impl std::error::Error for RecordError {}

fn signed_message(payload: &[u8]) -> Vec<u8> {
    [RECORD_CTX, payload].concat()
}

impl Record {
    pub fn sign(secret: &GroupSecret, entry: &Entry) -> Self {
        let payload = postcard::to_stdvec(entry).expect("entry serializes");
        Record { sig: secret.sign(&signed_message(&payload)), payload }
    }

    /// Decodes and verifies against the group named in the entry.
    pub fn open(&self) -> Result<Entry, RecordError> {
        if self.payload.len() > MAX_RECORD_LEN {
            return Err(RecordError::TooLarge);
        }
        let e: Entry = postcard::from_bytes(&self.payload).map_err(|_| RecordError::Encoding)?;
        e.group
            .verifying_key()
            .verify_strict(&signed_message(&self.payload), &self.sig)
            .map_err(|_| RecordError::BadSignature)?;
        let consistent = e.id == e.body.id()
            && match &e.body {
                // signed by the group anyway, but must be a valid certificate of this group
                Body::Cert(c) => c.verify(&e.group, None).is_ok(),
                Body::Revoke { .. } | Body::Epoch { .. } | Body::EpochKey { .. } => true,
            };
        if !consistent {
            return Err(RecordError::Inconsistent);
        }
        Ok(e)
    }
}

pub fn record_key(group: &GroupId, id: &str) -> RecordKey {
    let h = Blake2s256::new().chain_update(group.as_bytes()).chain_update(id.as_bytes()).finalize();
    h[..16].try_into().unwrap()
}

/// Whether `cert` is revoked: its node, or the join key it was enrolled with.
pub fn cert_revoked(revoked: &HashSet<NodeId>, cert: &Cert) -> bool {
    revoked.contains(&cert.body.node) || cert.join_key().is_some_and(|k| revoked.contains(&k))
}

/// Who may be in a group according to its records: a snapshot for the packet path and trackers.
#[derive(Clone, Debug, Default)]
pub struct Membership {
    pub revoked: HashSet<NodeId>,
    /// Nodes with a certificate issued by an admin (record `cert/<node>`).
    pub issued: HashSet<NodeId>,
}

impl Membership {
    pub fn of(store: &StateStore, group: &GroupId) -> Self {
        Membership { revoked: store.revoked(group), issued: store.certs(group).iter().map(|c| c.body.node).collect() }
    }

    /// Whether a (verified) certificate still admits its node. When an admin turns an invite
    /// certificate into a regular one, it revokes the join key; until the node picks up its new
    /// certificate it still presents the old one, which stays good because a regular one exists.
    pub fn admits(&self, cert: &Cert) -> bool {
        let node = cert.body.node;
        if self.revoked.contains(&node) {
            return false;
        }
        cert.join_key().is_none_or(|k| !self.revoked.contains(&k) || self.issued.contains(&node))
    }
}

struct Stored {
    entry: Entry,
    record: Record,
}

#[derive(Default)]
struct Inner {
    groups: HashMap<GroupId, HashMap<RecordKey, Stored>>,
    file_mtime: Option<SystemTime>,
}

impl Inner {
    /// LWW insert of a verified record; returns the entry if it changed the state.
    fn insert(&mut self, record: Record, now: u64) -> Result<Option<Entry>, RecordError> {
        let e = record.open()?;
        // with a clock that is certainly wrong (1970 before NTP) everything looks "future"
        if crate::clock::trusted() && e.ts > now + MAX_CLOCK_SKEW_MS {
            return Err(RecordError::FromTheFuture);
        }
        let records = self.groups.entry(e.group).or_default();
        let key = record_key(&e.group, &e.id);
        match records.get(&key) {
            Some(old) if (old.entry.ts, &old.record.payload) >= (e.ts, &record.payload) => return Ok(None),
            None if records.len() >= MAX_GROUP_RECORDS => return Err(RecordError::Full),
            _ => {}
        }
        records.insert(key, Stored { entry: e.clone(), record });
        Ok(Some(e))
    }

    fn live(&self, group: &GroupId) -> impl Iterator<Item = &Entry> {
        self.groups.get(group).into_iter().flat_map(|r| r.values()).map(|s| &s.entry).filter(|e| !e.deleted)
    }
}

/// The records of all groups a node (or tracker) knows.
pub struct StateStore {
    path: Option<PathBuf>,
    inner: Mutex<Inner>,
}

fn read_file(path: &Path) -> Vec<Record> {
    match std::fs::read(path) {
        Ok(b) => postcard::from_bytes(&b).unwrap_or_else(|e| {
            log::warn!("State | {} unreadable ({e}), starting empty", path.display());
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

impl StateStore {
    /// In memory only (trackers, tests).
    pub fn memory() -> Self {
        StateStore { path: None, inner: Mutex::new(Inner::default()) }
    }

    /// Backed by `path` (a missing file is an empty state). Records are re-verified on load.
    pub fn open(path: PathBuf) -> Self {
        let s = StateStore { path: Some(path), inner: Mutex::new(Inner::default()) };
        s.reload();
        s
    }

    /// Inserts verified records; returns the entries that changed the state.
    pub fn insert(&self, records: impl IntoIterator<Item = Record>) -> Vec<Entry> {
        let now = now_ms();
        let mut inner = self.inner.lock();
        let mut changed = Vec::new();
        for r in records {
            match inner.insert(r, now) {
                Ok(Some(e)) => changed.push(e),
                Ok(None) => {}
                Err(e) => log::debug!("State | record refused: {e}"),
            }
        }
        changed
    }

    /// Picks up records written to the file by another process (the CLI), merging them in.
    pub fn reload(&self) -> Vec<Entry> {
        let Some(path) = &self.path else { return Vec::new() };
        let m = mtime(path);
        if m.is_none() || m == self.inner.lock().file_mtime {
            return Vec::new();
        }
        let changed = self.insert(read_file(path));
        self.inner.lock().file_mtime = m;
        changed
    }

    /// Writes all records, merged with what the file holds now (another process may have added some).
    pub fn save(&self) {
        let Some(path) = &self.path else { return };
        self.insert(read_file(path));
        let mut inner = self.inner.lock();
        let all: Vec<&Record> = inner.groups.values().flat_map(|r| r.values()).map(|s| &s.record).collect();
        let data = postcard::to_stdvec(&all).expect("records serialize");
        let tmp = path.with_extension("tmp");
        match std::fs::write(&tmp, data).and_then(|_| std::fs::rename(&tmp, path)) {
            Ok(()) => inner.file_mtime = mtime(path),
            Err(e) => log::warn!("State | write {} error: {e}", path.display()),
        }
    }

    /// Signs and stores a new record with a timestamp after any earlier one of the same id.
    pub fn add(&self, secret: &GroupSecret, body: Body, deleted: bool) -> Entry {
        let group = secret.id();
        let id = body.id();
        let key = record_key(&group, &id);
        let mut inner = self.inner.lock();
        let prev = inner.groups.get(&group).and_then(|r| r.get(&key)).map_or(0, |s| s.entry.ts);
        let entry = Entry { group, id, ts: now_ms().max(prev + 1), deleted, body };
        inner.insert(Record::sign(secret, &entry), now_ms()).expect("own record is valid");
        entry
    }

    pub fn revoked(&self, group: &GroupId) -> HashSet<NodeId> {
        self.inner
            .lock()
            .live(group)
            .filter_map(|e| match &e.body {
                Body::Revoke { key } => Some(*key),
                _ => None,
            })
            .collect()
    }

    /// The certificate admins issued for `node`, if any.
    pub fn cert(&self, group: &GroupId, node: &NodeId) -> Option<Cert> {
        let inner = self.inner.lock();
        let s = inner.groups.get(group)?.get(&record_key(group, &format!("cert/{node}")))?;
        match &s.entry.body {
            Body::Cert(c) if !s.entry.deleted => Some((**c).clone()),
            _ => None,
        }
    }

    pub fn certs(&self, group: &GroupId) -> Vec<Cert> {
        self.inner
            .lock()
            .live(group)
            .filter_map(|e| match &e.body {
                Body::Cert(c) => Some((**c).clone()),
                _ => None,
            })
            .collect()
    }

    /// The newest psk epoch and its switch time (unix ms), if one was announced.
    pub fn epoch(&self, group: &GroupId) -> Option<(u32, u64)> {
        let inner = self.inner.lock();
        inner.live(group).find_map(|e| match e.body {
            Body::Epoch { epoch, active_from } => Some((epoch, active_from)),
            _ => None,
        })
    }

    /// The psk of `epoch` sealed to us, if there is one.
    pub fn epoch_psk(&self, group: &GroupId, identity: &Identity, epoch: u32) -> Option<[u8; 32]> {
        let inner = self.inner.lock();
        let s = inner.groups.get(group)?.get(&record_key(group, &format!("epochkey/{}", identity.id())))?;
        match &s.entry.body {
            Body::EpochKey { epoch: e, eph, sealed, .. } if *e == epoch && !s.entry.deleted => {
                open_psk(group, identity, epoch, eph, sealed)
            }
            _ => None,
        }
    }

    /// Whether `node` has the psk of `epoch` sealed to it.
    pub fn has_epoch_key(&self, group: &GroupId, node: &NodeId, epoch: u32) -> bool {
        let inner = self.inner.lock();
        inner
            .live(group)
            .any(|e| matches!(e.body, Body::EpochKey { node: n, epoch: x, .. } if n == *node && x == epoch))
    }

    /// Starts psk epoch `after + 1` (or the next after any announced one) at `now + lead_ms`:
    /// the epoch record and the new psk sealed to every member with an issued certificate that is
    /// not revoked. Returns the new records.
    pub fn rotate(&self, secret: &GroupSecret, after: u32, lead_ms: u64) -> Vec<Entry> {
        let g = secret.id();
        let epoch = self.epoch(&g).map_or(after, |(e, _)| e.max(after)) + 1;
        let psk = secret.psk(epoch);
        let m = Membership::of(self, &g);
        let mut out = vec![self.add(secret, Body::Epoch { epoch, active_from: now_ms() + lead_ms }, false)];
        for c in self.certs(&g).iter().filter(|c| m.admits(c)) {
            out.push(self.add(secret, seal_psk(&g, &c.body.node, epoch, &psk), false));
        }
        out
    }

    pub fn summary(&self, group: &GroupId) -> Vec<(RecordKey, u64)> {
        let inner = self.inner.lock();
        inner.groups.get(group).map_or_else(Vec::new, |r| r.iter().map(|(k, s)| (*k, s.entry.ts)).collect())
    }

    /// Compares the other side's summary with ours: the records it lacks (or has older), and the
    /// keys of the ones it has newer.
    pub fn diff(&self, group: &GroupId, theirs: &[(RecordKey, u64)]) -> (Vec<Record>, Vec<RecordKey>) {
        let inner = self.inner.lock();
        let empty = HashMap::new();
        let ours = inner.groups.get(group).unwrap_or(&empty);
        let theirs: HashMap<RecordKey, u64> = theirs.iter().copied().collect();
        let give = ours
            .iter()
            .filter(|(k, s)| theirs.get(*k).is_none_or(|&t| t < s.entry.ts))
            .map(|(_, s)| s.record.clone())
            .collect();
        let want =
            theirs.iter().filter(|(k, t)| ours.get(*k).is_none_or(|s| s.entry.ts < **t)).map(|(k, _)| *k).collect();
        (give, want)
    }

    pub fn get(&self, group: &GroupId, keys: &[RecordKey]) -> Vec<Record> {
        let inner = self.inner.lock();
        let Some(r) = inner.groups.get(group) else { return Vec::new() };
        keys.iter().filter_map(|k| r.get(k)).map(|s| s.record.clone()).collect()
    }
}

/// Anti-entropy between two stores, over a tracker session or a peer session (kind STATE).
#[derive(Debug, Serialize, Deserialize)]
pub enum SyncMsg {
    /// "These are the records I have": the other side answers with what is missing on either end.
    Summary {
        group: GroupId,
        items: Vec<(RecordKey, u64)>,
    },
    Want {
        group: GroupId,
        keys: Vec<RecordKey>,
    },
    Records {
        records: Vec<Record>,
    },
}

impl SyncMsg {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("sync message serializes")
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        postcard::from_bytes(b).ok()
    }

    /// Our summary of `group`, split to fit datagrams (one message even when empty, so the other
    /// side sends us everything it has).
    pub fn summaries(store: &StateStore, group: &GroupId) -> Vec<SyncMsg> {
        let items = store.summary(group);
        if items.is_empty() {
            return vec![SyncMsg::Summary { group: *group, items }];
        }
        items.chunks(SUMMARY_CHUNK).map(|c| SyncMsg::Summary { group: *group, items: c.to_vec() }).collect()
    }

    /// `records` packed into messages of about one datagram each.
    pub fn records(records: Vec<Record>) -> Vec<SyncMsg> {
        let mut out = Vec::new();
        let (mut cur, mut size) = (Vec::new(), 0);
        for r in records {
            let n = r.payload.len() + 70;
            if !cur.is_empty() && size + n > RECORDS_BUDGET {
                out.push(SyncMsg::Records { records: std::mem::take(&mut cur) });
                size = 0;
            }
            size += n;
            cur.push(r);
        }
        if !cur.is_empty() {
            out.push(SyncMsg::Records { records: cur });
        }
        out
    }

    /// Handles a message from the other side. `allowed` says which groups may be synced with it
    /// (groups it is a verified member of, and that we are in). Returns the replies and the
    /// entries that changed our state.
    pub fn handle(self, store: &StateStore, allowed: impl Fn(&GroupId) -> bool) -> (Vec<SyncMsg>, Vec<Entry>) {
        match self {
            SyncMsg::Summary { group, items } if allowed(&group) => {
                let (give, want) = store.diff(&group, &items);
                let mut out = Self::records(give);
                for c in want.chunks(SUMMARY_CHUNK) {
                    out.push(SyncMsg::Want { group, keys: c.to_vec() });
                }
                (out, Vec::new())
            }
            SyncMsg::Want { group, keys } if allowed(&group) => (Self::records(store.get(&group, &keys)), Vec::new()),
            SyncMsg::Records { records } => {
                let ok = records.into_iter().filter(|r| r.open().is_ok_and(|e| allowed(&e.group)));
                (Vec::new(), store.insert(ok))
            }
            _ => (Vec::new(), Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::CertBody;
    use crate::identity::Identity;

    fn sync(a: &StateStore, b: &StateStore, group: &GroupId) {
        // a -> b summary, b answers, a answers the wants
        for m in SyncMsg::summaries(a, group) {
            let (replies, _) = m.handle(b, |_| true);
            for r in replies {
                let (back, _) = r.handle(a, |_| true);
                for x in back {
                    x.handle(b, |_| true);
                }
            }
        }
    }

    #[test]
    fn records_verify_and_lww() {
        let g = GroupSecret::generate();
        let s = StateStore::memory();
        let victim = Identity::generate().id();
        let e = s.add(&g, Body::Revoke { key: victim }, false);
        assert!(s.revoked(&g.id()).contains(&victim));
        // a newer tombstone wins, an older record does not come back
        let old = s.get(&g.id(), &[record_key(&g.id(), &e.id)]);
        s.add(&g, Body::Revoke { key: victim }, true);
        assert!(s.revoked(&g.id()).is_empty());
        assert!(s.insert(old).is_empty());
        assert!(s.revoked(&g.id()).is_empty());
    }

    #[test]
    fn forged_and_inconsistent_records_refused() {
        let (g, other) = (GroupSecret::generate(), GroupSecret::generate());
        let key = Identity::generate().id();
        let mut e = Entry {
            group: g.id(),
            id: format!("revoke/{key}"),
            ts: now_ms(),
            deleted: false,
            body: Body::Revoke { key },
        };
        assert_eq!(Record::sign(&other, &e).open(), Err(RecordError::BadSignature));
        let mut tampered = Record::sign(&g, &e);
        *tampered.payload.last_mut().unwrap() ^= 1;
        assert!(tampered.open().is_err());
        e.id = "revoke/somebody-else".into();
        assert_eq!(Record::sign(&g, &e).open(), Err(RecordError::Inconsistent));
        // a certificate of another group, wrapped in this group's record
        let c = other.issue(CertBody::new(key, "x", vec![]));
        let e = Entry {
            group: g.id(),
            id: format!("cert/{key}"),
            ts: now_ms(),
            deleted: false,
            body: Body::Cert(Box::new(c)),
        };
        assert_eq!(Record::sign(&g, &e).open(), Err(RecordError::Inconsistent));
        // too far in the future
        let e = Entry {
            group: g.id(),
            id: format!("revoke/{key}"),
            ts: now_ms() + 2 * MAX_CLOCK_SKEW_MS,
            deleted: false,
            body: Body::Revoke { key },
        };
        assert!(StateStore::memory().insert([Record::sign(&g, &e)]).is_empty());
    }

    #[test]
    fn sync_converges_both_ways() {
        let g = GroupSecret::generate();
        let (a, b) = (StateStore::memory(), StateStore::memory());
        let (x, y, z) = (Identity::generate().id(), Identity::generate().id(), Identity::generate().id());
        a.add(&g, Body::Revoke { key: x }, false);
        a.add(&g, Body::Cert(Box::new(g.issue(CertBody::new(z, "z", vec![])))), false);
        b.add(&g, Body::Revoke { key: y }, false);
        sync(&a, &b, &g.id());
        assert_eq!(a.revoked(&g.id()), HashSet::from([x, y]));
        assert_eq!(b.revoked(&g.id()), HashSet::from([x, y]));
        assert_eq!(b.cert(&g.id(), &z).unwrap().body.name, "z");
        // nothing left to exchange
        let (give, want) = a.diff(&g.id(), &b.summary(&g.id()));
        assert!(give.is_empty() && want.is_empty());
    }

    #[test]
    fn sync_respects_allowed_groups() {
        let (g, h) = (GroupSecret::generate(), GroupSecret::generate());
        let (a, b) = (StateStore::memory(), StateStore::memory());
        a.add(&h, Body::Revoke { key: Identity::generate().id() }, false);
        let records = a.get(&h.id(), &a.summary(&h.id()).iter().map(|(k, _)| *k).collect::<Vec<_>>());
        let (_, changed) = SyncMsg::Records { records }.handle(&b, |grp| *grp == g.id());
        assert!(changed.is_empty() && b.summary(&h.id()).is_empty());
        let (replies, _) = SyncMsg::Summary { group: h.id(), items: vec![] }.handle(&a, |grp| *grp == g.id());
        assert!(replies.is_empty(), "no records of a group the other side is not in");
    }

    #[test]
    fn file_persistence_and_merge() {
        let dir = std::env::temp_dir()
            .join(format!("dvpn-state-{}", crate::crypto::encode_b64(&crate::crypto::random_bytes::<6>())));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.bin");
        let g = GroupSecret::generate();
        let (x, y) = (Identity::generate().id(), Identity::generate().id());
        let daemon = StateStore::open(path.clone());
        daemon.add(&g, Body::Revoke { key: x }, false);
        daemon.save();
        // the CLI adds a record while the daemon runs
        let cli = StateStore::open(path.clone());
        cli.add(&g, Body::Revoke { key: y }, false);
        std::thread::sleep(std::time::Duration::from_millis(20)); // distinct mtime
        cli.save();
        let changed = daemon.reload();
        assert_eq!(changed.len(), 1);
        assert_eq!(daemon.revoked(&g.id()), HashSet::from([x, y]));
        daemon.save();
        assert_eq!(StateStore::open(path).revoked(&g.id()).len(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn revocation_covers_join_keys() {
        let g = GroupSecret::generate();
        let join = g.grant_join(CertBody::new(Identity::generate().id(), "n", vec![]), u64::MAX);
        let cert = join.enroll(Identity::generate().id());
        assert!(!cert_revoked(&HashSet::new(), &cert));
        assert!(cert_revoked(&HashSet::from([join.grant.key]), &cert));
        assert!(cert_revoked(&HashSet::from([cert.body.node]), &cert));
    }

    #[test]
    fn membership_admits() {
        let g = GroupSecret::generate();
        let s = StateStore::memory();
        let join = g.grant_join(CertBody::new(Identity::generate().id(), "n", vec![]), u64::MAX);
        let (a, b) = (Identity::generate().id(), Identity::generate().id());
        let (ca, cb) = (join.enroll(a), join.enroll(b));
        assert!(Membership::of(&s, &g.id()).admits(&ca));
        // the admin converts a: regular cert for a, join key revoked
        s.add(&g, Body::Cert(Box::new(g.issue(ca.body.clone()))), false);
        s.add(&g, Body::Revoke { key: join.grant.key }, false);
        let m = Membership::of(&s, &g.id());
        assert!(m.admits(&ca), "a still shows its invite cert until it picks up the new one");
        assert!(!m.admits(&cb), "the invite cannot be used by a second node");
        s.add(&g, Body::Revoke { key: a }, false);
        let m = Membership::of(&s, &g.id());
        assert!(!m.admits(&ca) && !m.admits(&g.issue(ca.body.clone())));
    }

    #[test]
    fn psk_rotation_reaches_members_only() {
        let g = GroupSecret::generate();
        let s = StateStore::memory();
        let (a, b, x) = (Identity::generate(), Identity::generate(), Identity::generate());
        for i in [&a, &b, &x] {
            s.add(&g, Body::Cert(Box::new(g.issue(CertBody::new(i.id(), "n", vec![])))), false);
        }
        s.add(&g, Body::Revoke { key: x.id() }, false);
        let changed = s.rotate(&g, 0, 60_000);
        assert_eq!(changed.len(), 3, "epoch + a + b, not the revoked x");
        let (epoch, at) = s.epoch(&g.id()).unwrap();
        assert_eq!(epoch, 1);
        assert!(at > now_ms());
        assert_eq!(s.epoch_psk(&g.id(), &a, 1), Some(g.psk(1)));
        assert_eq!(s.epoch_psk(&g.id(), &b, 1), Some(g.psk(1)));
        assert_eq!(s.epoch_psk(&g.id(), &x, 1), None);
        assert_eq!(s.epoch_psk(&g.id(), &a, 2), None);
        // the record must be readable only with a's key
        let Some(Body::EpochKey { eph, sealed, .. }) = s.inner.lock().live(&g.id()).find_map(|e| match &e.body {
            Body::EpochKey { node, .. } if *node == a.id() => Some(e.body.clone()),
            _ => None,
        }) else {
            panic!()
        };
        assert_eq!(open_psk(&g.id(), &b, 1, &eph, &sealed), None);
        assert!(
            s.rotate(&g, 0, 0).len() == 3 && s.epoch(&g.id()).unwrap().0 == 2,
            "next rotation goes on from the announced epoch"
        );
    }

    #[test]
    fn records_messages_fit_datagrams() {
        let g = GroupSecret::generate();
        let s = StateStore::memory();
        for i in 0..30 {
            s.add(
                &g,
                Body::Cert(Box::new(g.issue(CertBody::new(Identity::generate().id(), &format!("node{i}"), vec![])))),
                false,
            );
        }
        let all = s.get(&g.id(), &s.summary(&g.id()).iter().map(|(k, _)| *k).collect::<Vec<_>>());
        let msgs = SyncMsg::records(all);
        assert!(msgs.len() > 1);
        for m in &msgs {
            assert!(m.encode().len() <= 1300, "{}", m.encode().len());
        }
    }
}
