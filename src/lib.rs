//! DVPN: decentralized P2P VPN. The binary (`main.rs`) is a thin CLI over these modules;
//! they are a library so that fuzz targets and benchmarks can reach the parsers.

pub mod acl;
pub mod aclfilter;
pub mod api;
pub mod apply;
pub mod backup;
pub mod ckr;
pub mod clock;
pub mod config;
pub mod crypto;
pub mod dns;
pub mod elligator;
pub mod exit;
pub mod gateway;
pub mod group;
pub mod identity;
pub mod link;
pub mod logger;
pub mod metrics;
pub mod node;
pub mod noise;
pub mod obfs;
pub mod ops;
pub mod packet;
pub mod plan;
pub mod proto;
pub mod replay;
pub mod router;
pub mod run;
pub mod state;
pub mod storage;
pub mod sysroute;
#[cfg(windows)]
pub mod sysroute_win;
pub mod tracker_client;
pub mod tracker_server;
pub mod transport;
pub mod tunnel;
#[cfg(windows)]
pub mod winnet;
