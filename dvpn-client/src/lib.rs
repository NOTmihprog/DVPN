//! Client of the local API of a [DVPN](https://git.mihprog.com/DVPN/DVPN) v4 node (`doc/api.md`
//! there): msgpack datagrams over a unix socket or UDP.
//!
//! ```no_run
//! # async fn demo() -> Result<(), dvpn_client::Error> {
//! use dvpn_client::{ApiAddr, Client};
//! let c = Client::connect(ApiAddr::detect(None), "my-app").await?;
//! println!("node {} in group {}", c.info().name, c.info().group_name);
//! for n in c.neighbors().await? {
//!     println!("{} {:?} ms", n.name.as_deref().unwrap_or(&n.key), n.rtt_ms);
//! }
//! # Ok(()) }
//! ```
//!
//! Licensed under MIT OR Apache-2.0 (the node itself is GPL-3.0; this crate speaks its protocol
//! and has none of its code).

mod addr;
mod client;
mod error;
mod transport;
pub mod types;
pub mod wire;

pub use addr::ApiAddr;
pub use client::Client;
pub use error::{Error, ErrorCode};
pub use types::*;

/// The API protocol version this library speaks (`init` `version`).
pub const API_VERSION: u64 = 4;
