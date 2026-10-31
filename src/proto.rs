//! Wire protocol (v3). Every UDP datagram starts with one type byte.
//!
//! Tracker (peer <-> discovery server):
//! ```text
//! HELLO      [0x01][client_eph x25519 32][nonce 16][zero padding up to HELLO_LEN]
//! HELLO_ACK  [0x02][server_eph x25519 32][ed25519 sig 64 over HELLO_SIG_CTX|client_eph|nonce|server_eph]
//! TRACKER    [0x03][counter u64 LE][chacha20poly1305(postcard(TrackerMsg))][tag 16]
//! ```
//! `Announce` carries an Ed25519 signature by the announced node key over
//! ANNOUNCE_SIG_CTX|client_eph|nonce|server_eph, binding the claim to this session.
//! HELLO is padded so the server reply is never larger than the request (no amplification).
//! Session keys: HKDF-SHA256(salt = nonce, ikm = x25519 shared, info = KEYS_CTX|client_eph|server_eph),
//! 64 bytes split into client->server and server->client keys, counters are replay-checked.
//!
//! Peer <-> peer:
//! ```text
//! SEALED     [0x10][nonce 24][xchacha20poly1305([route][payload])][tag 16]
//!            key = recipient's key, AAD = [0x10]|recipient_id
//! PLAIN      [0x11][route][payload]      only accepted when the recipient has no key
//! ```
//! Routes: 0 = control (ping/pong), 1 = IP packet for the TUN device, 32..=255 = API clients.
//! The sender of a packet is identified by its UDP source address. Control packets also carry
//! the sender id, which lets a peer whose NAT mapping changed be found at its new address:
//! ```text
//! CONTROL    [kind][echo_ts u64][session u64][seq u64][sender_id 32][random padding]
//! ```
//! `echo_ts` is the ping send time (echoed back in the pong, for RTT); (`session`, `seq`) is
//! random-per-run plus monotonic, so replayed control packets cannot move an endpoint.

use std::net::SocketAddr;

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::identity::NodeId;

pub const HELLO: u8 = 0x01;
pub const HELLO_ACK: u8 = 0x02;
pub const TRACKER: u8 = 0x03;
pub const SEALED: u8 = 0x10;
pub const PLAIN: u8 = 0x11;

pub const HELLO_LEN: usize = 128;
pub const HELLO_ACK_LEN: usize = 1 + 32 + 64;
pub const HELLO_SIG_CTX: &[u8] = b"dvpn/3 hello";
pub const KEYS_CTX: &[u8] = b"dvpn/3 tracker keys";
/// Signature context of `Announce` (signed by the node key over the session transcript).
pub const ANNOUNCE_SIG_CTX: &[u8] = b"dvpn/4 announce";

pub const ROUTE_CONTROL: u8 = 0;
pub const ROUTE_NET: u8 = 1;
pub const ROUTE_API_MIN: u8 = 32;
pub const ROUTE_API_MAX: u8 = 255;

pub const CONTROL_PING: u8 = 0;
pub const CONTROL_PONG: u8 = 1;
pub const CONTROL_LEN: usize = 1 + 8 + 8 + 8 + 32;
/// Packets from unknown addresses larger than this are not even tried (only control packets matter).
pub const ROAM_MAX_LEN: usize = 256;

pub const MAX_DATAGRAM: usize = 65507;

/// Max peer ids in a single `Search` so the datagram stays well under the MTU.
pub const SEARCH_BATCH: usize = 32;

#[derive(Debug, Serialize, Deserialize)]
pub enum TrackerMsg {
    /// Client -> server: "I am `peer_id`, at the address you see this packet from". `sig` is made
    /// with `peer_id`'s key over this session's handshake transcript
    /// (`TrackerSession::announce_msg`), so only the key owner can announce it.
    Announce {
        peer_id: NodeId,
        sig: Signature,
    },
    /// Client -> server: "I want to connect to these peers".
    Search {
        peers: Vec<NodeId>,
    },
    /// Server -> client: `peer_id` is reachable at `addr`. Sent for our own id in reply to
    /// an announce, and for a searched peer once both sides searched for each other.
    Found {
        peer_id: NodeId,
        addr: SocketAddr,
    },
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
