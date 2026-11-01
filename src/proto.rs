//! Wire protocol. Every datagram is masked (`obfs.rs`): sessions with trackers look like
//! sessions between nodes (`tunnel.rs`, keys derived from the tracker's public key), and are
//! told apart by the sender's address only.
//!
//! Peer <-> peer, logical layout (on the wire padded and header-masked by `obfs.rs`):
//! ```text
//! HS_INIT  [0x20][pad u16][sender_idx u32 LE][Noise message 1]
//! HS_RESP  [0x21][pad u16][sender_idx u32 LE][receiver_idx u32 LE][Noise message 2]
//! DATA     [0x23][pad u16][receiver_idx u32 LE][counter u64 LE][chacha20poly1305([kind][body])][tag 16]
//! ```
//! Noise messages start with the Elligator2 representative of the ephemeral key. Indices are
//! random per session; the receiver finds the session by `receiver_idx`, so the sender's
//! address plays no role in authentication. The DATA header (padding length included) is the
//! AEAD's associated data. Kinds: 0 = control (ping/pong), 1 = IP packet for the TUN device, 2 = group
//! records (`state::SyncMsg`), 32..=255 = API clients.
//! ```text
//! CONTROL  [0][PING|PONG][echo_ts u64 LE][random padding]
//! ```

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::group::Cert;
use crate::state::SyncMsg;

pub const HS_INIT: u8 = 0x20;
pub const HS_RESP: u8 = 0x21;
pub const DATA: u8 = 0x23;
pub const HS_INIT_HDR: usize = 1 + 2 + 4;
pub const HS_RESP_HDR: usize = 1 + 2 + 4 + 4;
pub const DATA_HDR: usize = 1 + 2 + 4 + 8;

pub const KIND_CONTROL: u8 = 0;
pub const KIND_IP: u8 = 1;
/// Group records between neighbours: `SyncMsg`.
pub const KIND_STATE: u8 = 2;
/// Mesh routing between neighbours: `router::RoutingMsg`.
pub const KIND_ROUTING: u8 = 3;
/// A packet for another node: `[limit u8][hops u8][probe u16][dst8][src8][inner]`, where inner
/// is a packet of the end-to-end session with dst (PLAN §4.3, §6).
pub const KIND_FORWARD: u8 = 4;
pub const FORWARD_HDR: usize = 1 + 1 + 2 + 8 + 8;
/// Hop limit of forwarded packets (PLAN §6.4).
pub const MAX_HOPS: u8 = 16;
pub const KIND_API_MIN: u8 = 32;
pub const KIND_API_MAX: u8 = 255;

pub const CONTROL_PING: u8 = 0;
pub const CONTROL_PONG: u8 = 1;
pub const CONTROL_LEN: usize = 1 + 1 + 8;

pub const MAX_DATAGRAM: usize = 65507;

/// Most groups one announce may list.
pub const MAX_ANNOUNCE_CERTS: usize = 16;
/// Most address candidates a node announces (PLAN §9.1).
pub const MAX_CANDIDATES: usize = 8;

#[derive(Debug, Serialize, Deserialize)]
pub enum TrackerMsg {
    /// Client -> server: "I am at the address you see this packet from, a member of the groups
    /// of these certificates". Who "I" is, the session handshake proved (the client's static key
    /// is its node key); the server checks each certificate against its group id (PLAN §11).
    /// `candidates` are the node's own interface addresses with its port (LAN, IPv6), tried by
    /// peers besides the address the tracker sees.
    Announce {
        certs: Vec<Cert>,
        candidates: Vec<SocketAddr>,
    },
    /// Server -> client: the member with this certificate is reachable at `addr`. Sent for every
    /// online member of the client's groups in reply to an announce (the client's own address
    /// included), and to all members when a node comes online or moves.
    Found {
        cert: Box<Cert>,
        addr: SocketAddr,
        candidates: Vec<SocketAddr>,
    },
    /// Group records both ways (`state.rs`), for the groups the client is a verified member of.
    Sync(SyncMsg),
    Close,
}

impl TrackerMsg {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("TrackerMsg serialization is infallible")
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        postcard::from_bytes(b).ok()
    }
}
