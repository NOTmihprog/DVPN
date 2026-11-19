//! Pipes: an API route (32..=255) as a datagram socket of one's own between members.
//!
//! Packets for a route with a pipe go to that pipe alone, through a queue of its own: they are
//! not copied into [`crate::Client::raw_events`] or [`crate::Client::net_packets`], and a slow
//! pipe neither holds up nor loses packets of anybody else. What comes while the queue is full is
//! dropped and counted ([`PipeReceiver::dropped`]).
//!
//! Sending has a variant without waiting ([`PipeSender::try_send`] with
//! [`PipeSender::poll_send_ready`]) and receiving one by polling ([`PipeReceiver::poll_recv`]),
//! for transports driven by `poll_*` (QUIC's `AsyncUdpSocket`, for one).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use rmpv::Value;
use tokio::sync::mpsc;

use crate::client::Shared;
use crate::wire::{encode, map};
use crate::{Error, MAX_PAYLOAD, NetPacket};

/// Packets a pipe's queue holds by default.
pub const PIPE_QUEUE: usize = 4096;

/// Where the receive task puts a pipe's packets.
pub(crate) struct PipeSlot {
    pub(crate) tx: mpsc::Sender<NetPacket>,
    pub(crate) dropped: Arc<AtomicU64>,
}

/// Gives the route back when the last half of the pipe is gone.
struct Owner {
    shared: Arc<Shared>,
    route: u8,
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.shared.pipes.lock().unwrap().remove(&self.route);
        self.shared.routes.lock().unwrap().remove(&self.route);
        // no answer awaited: if it is lost, the node frees the route when the client goes
        let del = self.shared.message("route", Some("del"), 0, vec![("route", Value::from(self.route))]);
        let _ = self.shared.sock().try_send(&del);
    }
}

/// An API route held by this client, from [`crate::Client::pipe`]. Dropping it gives the route
/// back; [`Pipe::split`] gives halves to send and receive from different tasks.
pub struct Pipe {
    tx: PipeSender,
    rx: PipeReceiver,
}

impl Pipe {
    /// The largest packet that goes through relays.
    pub const MAX_PAYLOAD: usize = MAX_PAYLOAD;

    pub(crate) fn new(shared: Arc<Shared>, route: u8, rx: mpsc::Receiver<NetPacket>, dropped: Arc<AtomicU64>) -> Pipe {
        let owner = Arc::new(Owner { shared: shared.clone(), route });
        Pipe {
            tx: PipeSender { shared, route, _owner: owner.clone() },
            rx: PipeReceiver { rx, dropped, _owner: owner },
        }
    }

    pub fn route(&self) -> u8 {
        self.tx.route
    }

    /// See [`PipeSender::send`].
    pub async fn send(&self, node: &str, data: &[u8]) -> Result<(), Error> {
        self.tx.send(node, data).await
    }

    /// See [`PipeReceiver::recv`].
    pub async fn recv(&mut self) -> Option<NetPacket> {
        self.rx.recv().await
    }

    /// The halves: the sender can be cloned; the route is given back when both are gone.
    pub fn split(self) -> (PipeSender, PipeReceiver) {
        (self.tx, self.rx)
    }
}

/// The sending half of a [`Pipe`].
#[derive(Clone)]
pub struct PipeSender {
    shared: Arc<Shared>,
    route: u8,
    _owner: Arc<Owner>,
}

impl PipeSender {
    pub fn route(&self) -> u8 {
        self.route
    }

    fn message(&self, node: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() > MAX_PAYLOAD {
            return Err(Error::PacketTooLarge { len: data.len(), max: MAX_PAYLOAD });
        }
        Ok(encode(&map(vec![
            ("type", "net".into()),
            ("rou", self.route.into()),
            ("key", node.into()),
            ("pack", Value::Binary(data.to_vec())),
        ])))
    }

    /// Sends `data` to member `node` (key, key prefix or name), straight or through relays. Like
    /// UDP: no answer, delivery not guaranteed.
    pub async fn send(&self, node: &str, data: &[u8]) -> Result<(), Error> {
        let m = self.message(node, data)?;
        self.shared.sock().send(&m).await.map_err(Error::from)
    }

    /// [`PipeSender::send`] without waiting: `Error::Io` of kind `WouldBlock` when the socket to the
    /// node is full ([`PipeSender::poll_send_ready`] tells when to try again).
    pub fn try_send(&self, node: &str, data: &[u8]) -> Result<(), Error> {
        let m = self.message(node, data)?;
        self.shared.sock().try_send(&m).map_err(Error::from)
    }

    /// Ready when [`PipeSender::try_send`] may go through.
    pub fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.shared.sock().poll_send_ready(cx)
    }
}

/// The receiving half of a [`Pipe`].
pub struct PipeReceiver {
    rx: mpsc::Receiver<NetPacket>,
    dropped: Arc<AtomicU64>,
    _owner: Arc<Owner>,
}

impl PipeReceiver {
    /// The next packet from a member; None once the client is gone.
    pub async fn recv(&mut self) -> Option<NetPacket> {
        self.rx.recv().await
    }

    /// The next packet without waiting.
    pub fn try_recv(&mut self) -> Option<NetPacket> {
        self.rx.try_recv().ok()
    }

    /// [`PipeReceiver::recv`] by polling.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<NetPacket>> {
        self.rx.poll_recv(cx)
    }

    /// Up to `limit` packets at once into `out`; `Ready(0)` once the client is gone.
    pub fn poll_recv_many(&mut self, cx: &mut Context<'_>, out: &mut Vec<NetPacket>, limit: usize) -> Poll<usize> {
        self.rx.poll_recv_many(cx, out, limit)
    }

    /// Packets dropped because the queue was full, since the pipe was made.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}
