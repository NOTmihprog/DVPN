//! Windows routing through the IP Helper API (PLAN 4.5): the default route of the physical
//! network, routes of our own, and pinning a socket to an interface (`IP_UNICAST_IF`), which
//! is what fwmark is on Linux: DVPN's own packets leave through the physical interface even
//! when our routes send everything else into Wintun (as wireguard-windows does).
//!
//! Our routes are told apart by their metric ([`TAG_METRIC`]): routes on the Wintun interface go
//! away with it, but the holes (`~` / `!` entries) go through the physical gateway and would stay
//! after a crash; they are removed by their metric on the next start.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN_ADDR, IN6_ADDR, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF,
    MIB_IPPROTO_NETMGMT, SOCKADDR_INET, SOCKET, setsockopt,
};

/// The route metric of our routes: unusual enough to find them again after a crash.
pub const TAG_METRIC: u32 = 7347;

fn err(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

fn family(v6: bool) -> ADDRESS_FAMILY {
    if v6 { AF_INET6 } else { AF_INET }
}

fn sockaddr(a: IpAddr) -> SOCKADDR_INET {
    let mut s = SOCKADDR_INET::default();
    match a {
        IpAddr::V4(v4) => {
            s.Ipv4.sin_family = AF_INET;
            s.Ipv4.sin_addr = IN_ADDR::default();
            s.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            s.Ipv6.sin6_family = AF_INET6;
            s.Ipv6.sin6_addr = IN6_ADDR::default();
            s.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    s
}

fn ip_of(s: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: the family says which member of the union is set
    unsafe {
        match s.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(s.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(s.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

/// A route as Windows has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub net: IpNet,
    pub if_index: u32,
    /// `None`: on-link (the Wintun interface).
    pub next_hop: Option<IpAddr>,
    pub metric: u32,
}

fn row(r: &Route) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: initializes a row we own
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = r.if_index;
    row.DestinationPrefix.Prefix = sockaddr(r.net.network());
    row.DestinationPrefix.PrefixLength = r.net.prefix_len();
    let unspecified = match r.net {
        IpNet::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpNet::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    row.NextHop = sockaddr(r.next_hop.unwrap_or(unspecified));
    row.Metric = r.metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

/// Adds a route (one already there is fine).
pub fn add_route(r: &Route) -> io::Result<()> {
    // SAFETY: a valid, initialized row
    match unsafe { CreateIpForwardEntry2(&row(r)) } {
        NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        e => Err(err(e)),
    }
}

/// Removes a route (one already gone is fine).
pub fn del_route(r: &Route) -> io::Result<()> {
    // SAFETY: a valid, initialized row
    match unsafe { DeleteIpForwardEntry2(&row(r)) } {
        NO_ERROR | ERROR_NOT_FOUND => Ok(()),
        e => Err(err(e)),
    }
}

/// Every route of a family.
fn routes(v6: bool) -> io::Result<Vec<(Route, u8)>> {
    let mut t: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: Windows allocates the table; we free it below
    let e = unsafe { GetIpForwardTable2(family(v6), &mut t) };
    if e != NO_ERROR {
        return Err(err(e));
    }
    let mut out = Vec::new();
    // SAFETY: the table holds NumEntries rows
    unsafe {
        let rows = std::slice::from_raw_parts((*t).Table.as_ptr(), (*t).NumEntries as usize);
        for r in rows {
            let (Some(dst), Some(hop)) = (ip_of(&r.DestinationPrefix.Prefix), ip_of(&r.NextHop)) else { continue };
            let Ok(net) = IpNet::new(dst, r.DestinationPrefix.PrefixLength) else { continue };
            let route = Route {
                net,
                if_index: r.InterfaceIndex,
                next_hop: Some(hop).filter(|h| !h.is_unspecified()),
                metric: r.Metric,
            };
            out.push((route, r.Protocol as u8));
        }
        FreeMibTable(t as *const _);
    }
    Ok(out)
}

/// The metric of an interface for a family (added to the route's own).
fn interface_metric(if_index: u32, v6: bool) -> Option<u32> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: initializes a row we own, then Windows fills it
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = family(v6);
    row.InterfaceIndex = if_index;
    // SAFETY: as above
    let e = unsafe { GetIpInterfaceEntry(&mut row) };
    (e == NO_ERROR && row.Connected).then_some(row.Metric)
}

/// The physical network's default route for a family: the interface and gateway Windows would
/// use if our routes were not there (the lowest route + interface metric, not on `exclude`).
pub fn default_route(v6: bool, exclude: u32) -> Option<(u32, Option<IpAddr>)> {
    routes(v6)
        .ok()?
        .into_iter()
        .filter(|(r, _)| r.net.prefix_len() == 0 && r.if_index != exclude && r.metric != TAG_METRIC)
        .filter_map(|(r, _)| interface_metric(r.if_index, v6).map(|m| (r.metric.saturating_add(m), r)))
        .min_by_key(|(m, _)| *m)
        .map(|(_, r)| (r.if_index, r.next_hop))
}

/// Removes our routes left by a crashed run (by their metric).
pub fn remove_tagged() {
    for v6 in [false, true] {
        for (r, proto) in routes(v6).unwrap_or_default() {
            if r.metric == TAG_METRIC && i32::from(proto) == MIB_IPPROTO_NETMGMT {
                let _ = del_route(&r);
            }
        }
    }
}

/// Sends a socket's packets out of the given interfaces (0: as the routes say), IPv4 and IPv6.
/// A dual-stack socket takes both: its IPv4 traffic follows `IP_UNICAST_IF`.
pub fn pin_socket(sock: SOCKET, v4_index: u32, v6_index: u32, dual: bool) -> io::Result<()> {
    let set = |level: i32, opt: i32, v: u32| -> io::Result<()> {
        // SAFETY: a 4-byte value for an option that takes a DWORD
        let r = unsafe { setsockopt(sock, level, opt, (&v as *const u32).cast(), 4) };
        if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    };
    // IP_UNICAST_IF takes the index in network byte order, IPV6_UNICAST_IF in host order
    set(IPPROTO_IPV6, IPV6_UNICAST_IF, v6_index)?;
    if dual {
        set(IPPROTO_IP, IP_UNICAST_IF, v4_index.to_be())?;
    }
    Ok(())
}

/// Pins an IPv4-only socket.
pub fn pin_socket_v4(sock: SOCKET, v4_index: u32) -> io::Result<()> {
    // SAFETY: as in pin_socket
    let r = unsafe { setsockopt(sock, IPPROTO_IP, IP_UNICAST_IF, (&v4_index.to_be() as *const u32).cast(), 4) };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}
