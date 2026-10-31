//! DVPN: decentralized P2P VPN. The binary (`main.rs`) is a thin CLI over these modules;
//! they are a library so that fuzz targets and benchmarks can reach the parsers.

pub mod api;
pub mod config;
pub mod crypto;
pub mod identity;
pub mod logger;
pub mod node;
pub mod noise;
pub mod packet;
pub mod proto;
pub mod replay;
pub mod storage;
pub mod tracker_client;
pub mod tracker_server;
pub mod transport;
