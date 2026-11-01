#!/bin/sh
# End-to-end test without root: a tracker and three dvpn nodes in separate network
# namespaces, inside one unprivileged user+net+mount namespace.
#
#            wan 203.0.113.0/24 (bridge, the "internet")
#      ┌──────────────┬──────────────┬──────────────┐
#   tracker .1     nat1 .11       nat2 .12       node C .20
#                    │ masquerade     │ masquerade
#               node A 192.168.1.2  node B 192.168.2.2
#
# A and B are each behind their own NAT, so A<->B only works through hole punching.
# Overlay: A 10.10.33.1 (group admin), B 10.10.33.2, C 10.10.33.3 (joined by invite), all links
# encrypted.
#
#   tests/netns-e2e.sh                  # debug build, ~10 s
#   DVPN=target/release/dvpn tests/netns-e2e.sh
#   KEEP=1 tests/netns-e2e.sh           # keep the work dir (configs, logs)
#
# Needs: unshare, ip, nft, ping; optional: iperf3 (throughput), tcpdump (plaintext check),
# tracepath (traceroute through relays).
# Exits non-zero on the first failure.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
D=${DVPN:-$ROOT/target/debug/dvpn}
case $D in /*) ;; *) D=$ROOT/$D ;; esac

if [ -z "${IN_NETNS:-}" ]; then
    [ -x "$D" ] || { echo "build dvpn first (cargo build): $D" >&2; exit 2; }
    W=$(mktemp -d "${TMPDIR:-/tmp}/dvpn-e2e.XXXXXX")
    IN_NETNS=1 W=$W D=$D unshare -rnm "$0" && rc=0 || rc=$?
    if [ "$rc" -eq 0 ] && [ -z "${KEEP:-}" ]; then rm -rf "$W"; else echo "work dir: $W"; fi
    exit "$rc"
fi

# ---- inside the namespace -------------------------------------------------------------
cd "$W"
mount -t tmpfs none /run && mkdir -p /run/netns
ip link set lo up

PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; for f in "$W"/*.log; do echo "--- tail $f"; tail -n 20 "$f"; done >&2; exit 1; }
ok() { echo "ok: $*"; }
# wait_for SECONDS COMMAND...: retry once a second until the command succeeds.
wait_for() {
    t=$1; shift
    while [ "$t" -gt 0 ]; do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 1; t=$((t - 1))
    done
    return 1
}
nsx() { ns=$1; shift; ip netns exec "$ns" "$@"; }
bg() { # bg NAME NS COMMAND...: run in the background, log to NAME.log
    name=$1; ns=$2; shift 2
    ip netns exec "$ns" "$@" > "$W/$name.log" 2>&1 &
    PIDS="$PIDS $!"
}

# ---- topology -------------------------------------------------------------------------
for ns in wan nat1 nat2 a b c; do ip netns add $ns; nsx $ns ip link set lo up; done
nsx wan ip link add br0 type bridge
nsx wan ip addr add 203.0.113.1/24 dev br0
nsx wan ip link set br0 up

# wan_port NS ADDR: connect NS to the wan bridge with ADDR/24
wan_port() {
    ip link add "w-$1" type veth peer name wan0
    ip link set wan0 netns "$1"
    ip link set "w-$1" netns wan
    nsx wan ip link set "w-$1" master br0 up
    nsx "$1" ip addr add "$2/24" dev wan0
    nsx "$1" ip link set wan0 up
}
# nat NAT_NS LAN_NS N: LAN 192.168.N.0/24 behind NAT_NS, masqueraded to wan
nat() {
    ip link add lan0 type veth peer name up0
    ip link set lan0 netns "$1"; ip link set up0 netns "$2"
    nsx "$1" ip addr add "192.168.$3.1/24" dev lan0; nsx "$1" ip link set lan0 up
    nsx "$2" ip addr add "192.168.$3.2/24" dev up0; nsx "$2" ip link set up0 up
    nsx "$2" ip route add default via "192.168.$3.1"
    nsx "$1" sysctl -qw net.ipv4.ip_forward=1
    nsx "$1" nft -f - <<NFT
table ip nat {
    chain post { type nat hook postrouting priority 100; oifname "wan0" masquerade; }
}
# Like a home router: unsolicited packets from the wan are dropped. Without this, the
# peer's first punching packet gets a confirmed conntrack entry on the NAT itself, our
# outgoing flow then clashes with it and masquerade picks another port (symmetric NAT).
table ip filter {
    chain input { type filter hook input priority 0; iifname "wan0" ct state new drop; }
    chain forward { type filter hook forward priority 0; iifname "wan0" ct state new drop; }
}
# UDP sent from this LAN straight to another NAT: proves a punched direct path
table ip watch {
    counter nat2nat { }
    chain pass { type filter hook forward priority 0; oifname "wan0" ip daddr 203.0.113.11-203.0.113.12 meta l4proto udp counter name nat2nat; }
}
NFT
}
wan_port nat1 203.0.113.11
wan_port nat2 203.0.113.12
wan_port c 203.0.113.20
nat nat1 a 1
nat nat2 b 2
nsx a ping -c1 -W2 203.0.113.1 >/dev/null || fail "A cannot reach the wan"
# LANs behind nodes for site-to-site: la behind A (192.168.10.0/24), lc behind C (192.168.30.0/24)
lan() { # lan NODE_NS LAN_NS N
    ip link add lan1 type veth peer name up1
    ip link set lan1 netns "$1"; ip link set up1 netns "$2"
    nsx "$1" ip addr add "192.168.$3.1/24" dev lan1; nsx "$1" ip link set lan1 up
    nsx "$2" ip addr add "192.168.$3.2/24" dev up1; nsx "$2" ip link set up1 up
    nsx "$2" ip route add default via "192.168.$3.1"
    nsx "$1" sysctl -qw net.ipv4.ip_forward=1
}
for ns in la lc; do ip netns add $ns; nsx $ns ip link set lo up; done
lan a la 10
lan c lc 30
# C and A are gateways to the "internet" ([gateway]: forwarding, NAT, NDP proxy on C); C also
# has an IPv6 /64 on the wan, from which B gets a public address. These tables only count
# what the gateways forward.
nsx wan ip -6 addr add 2001:db8::1/64 dev br0 nodad
nsx c ip -6 addr add 2001:db8::20/64 dev wan0 nodad
for g in "c wan0" "a up0"; do
    set -- $g
    nsx "$1" nft -f - <<NFT
table ip exitcount {
    counter exited { }
    chain exits { type filter hook forward priority 0; iifname "dnet" oifname "$2" counter name exited; }
}
NFT
done
ok "topology up"

# ---- tracker --------------------------------------------------------------------------
mkdir trk
bg tracker wan "$D" --dir "$W/trk" server -a 203.0.113.1 -p 6485
wait_for 10 grep -q '^public_key' trk/config.toml || fail "tracker did not write its key"
TKEY=$(sed -n 's/^public_key = "\(.*\)"/\1/p' trk/config.toml)
[ -n "$TKEY" ] || fail "tracker key is empty"
ok "tracker up"

# Active probing: random datagrams of any size get no answer from the tracker.
if command -v python3 >/dev/null; then
    nsx c python3 -I -c '
import os, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.5)
for n in (1, 32, 64, 128, 200, 600, 1400):
    s.sendto(os.urandom(n), ("203.0.113.1", 6485))
try:
    s.recvfrom(2048)
    sys.exit("tracker answered a random probe")
except socket.timeout:
    pass
' || fail "tracker answered a probe"
    ok "tracker silent to random probes"
fi

# ---- nodes ----------------------------------------------------------------------------
# A creates the group (its admin) and invites B and C: no keys or peer lists are exchanged by
# hand, the invite carries the group psk, the tracker and a one-time join key.
# Every command gets --dir, otherwise dvpn would write config.toml next to the binary.
mkdir a b c
key=$("$D" --dir "$W/a" show-key)
[ ${#key} -eq 43 ] || fail "show-key printed '$key', want a 43-char key"
cat >> a/config.toml <<TOML

[servers.main]
addr = "203.0.113.1"
port = 6485
key = "$TKEY"
TOML
"$D" --dir "$W/a" group create e2e -a 10.10.33.1 -n a --route 192.168.10.0/24 >/dev/null || fail "group create"
join() { # join NAME ADDR [invite options]
    n=$1 addr=$2; shift 2
    inv=$("$D" --dir "$W/a" group invite -n "$n" -a "$addr" "$@" 2>/dev/null) || fail "invite for $n"
    set -- "$n"
    "$D" --dir "$W/$1" group join "$inv" >/dev/null || fail "$1 could not join"
    grep -q '203.0.113.1' "$1/config.toml" || fail "$1: the invite did not add the tracker"
}
join b 10.10.33.2 --route 2001:db8::50/128
join c 10.10.33.3 --route 192.168.30.0/24
printf '\n[gateway]\nwan = ["wan0"]\nndp_proxy = "wan0"\n' >> c/config.toml
printf '\n[gateway]\nwan = ["up0"]\n' >> a/config.toml
# B sends its internet traffic through C, or A if C is down (gateways by priority)
"$D" --dir "$W/b" exit --v4 c,a --v6 c >/dev/null || fail "b: exit"
"$D" --dir "$W/b" group list | grep -q 'e2e.*member.*10.10.33.2' || fail "b: group list"

# The admin's secret survives the admin node: a password-protected backup restores the group on
# another node (with a new key, or the old one with --with-key), and that node can invite.
DVPN_BACKUP_PASSWORD=e2e-backup-pw "$D" --dir "$W/a" group backup -o "$W/a.bak" 2>/dev/null || fail "backup"
mkdir r r2
! DVPN_BACKUP_PASSWORD=wrong "$D" --dir "$W/r" group restore -i "$W/a.bak" >/dev/null 2>&1 || fail "restore with a wrong password"
DVPN_BACKUP_PASSWORD=e2e-backup-pw "$D" --dir "$W/r" group restore -i "$W/a.bak" >/dev/null 2>&1 || fail "restore"
gid() { "$D" --dir "$W/$1" group list | awk -F'|' '/e2e/ {gsub(/ /, "", $3); print $3}'; }
[ "$(gid r)" = "$(gid a)" ] || fail "restored group id differs"
"$D" --dir "$W/r" group list | grep -q 'e2e.*admin.*10.10.33.1' || fail "restored node is not the admin"
"$D" --dir "$W/r" group invite -n z >/dev/null 2>&1 || fail "restored admin cannot invite"
DVPN_BACKUP_PASSWORD=e2e-backup-pw "$D" --dir "$W/r2" group restore --with-key -i "$W/a.bak" >/dev/null 2>&1 || fail "restore --with-key"
[ "$("$D" --dir "$W/r2" show-key)" = "$("$D" --dir "$W/a" show-key)" ] || fail "--with-key did not restore the node key"
ok "group backup restores the admin elsewhere"
# All namespaces share one /run, so the default unix API socket would collide: use UDP
# on each namespace's own loopback instead.
# C starts with its clock in 1970, like a router without RTC before NTP (a test-only offset
# read from a file): the tracker does not answer its stale handshakes, nobody reaches it.
echo -1700000000 > "$W/c.skew"
for n in a b; do bg "node-$n" $n "$D" --dir "$W/$n" -a 127.0.0.1:9902; done
bg node-c c env DVPN_TEST_CLOCK_SKEW_FILE="$W/c.skew" "$D" --dir "$W/c" -a 127.0.0.1:9902
for n in a b c; do
    wait_for 10 nsx $n ip -4 addr show dnet || fail "node $n: no tun interface"
done
ok "nodes up"
grep -q 'clock is earlier than this build' "$W/node-c.log" || fail "c did not notice its clock is wrong"
sleep 4
! grep -q 'Connection status connected' "$W/node-c.log" || fail "the tracker answered a handshake from 1970"
! nsx a ping -c1 -W1 10.10.33.3 >/dev/null 2>&1 || fail "c reachable while its clock is in 1970"
# "NTP" sets the clock: C connects by itself (handshake retries back off to at most 16 s)
echo 0 > "$W/c.skew"
wait_for 30 grep -q 'Connection status connected' "$W/node-c.log" || fail "c did not connect after its clock was set"
ok "c with a 1970 clock joins the network once the clock is set"

# ---- checks ---------------------------------------------------------------------------
# reach FROM TO_NAME TO_ADDR: overlay ping, first contact goes through tracker + punching
reach() {
    wait_for 30 nsx "$1" ping -c1 -W1 "$3" || fail "$1 -> $2 ($3): no ping"
    nsx "$1" ping -c3 -i0.2 -W1 "$3" >/dev/null || fail "$1 -> $2 ($3): packet loss"
    ok "$1 -> $2"
}
reach a c 10.10.33.3
reach b c 10.10.33.3
reach c a 10.10.33.1
reach a b 10.10.33.2   # both behind NAT: hole punching
reach b a 10.10.33.1

# Site-to-site: hosts in the LANs behind A and C reach each other through the A <-> C tunnel;
# A and C installed routes to the other LAN from the certificates (a separate routing table).
wait_for 20 nsx la ping -c1 -W1 192.168.30.2 || fail "la -> lc (site-to-site)"
nsx lc ping -c3 -i0.2 -W1 192.168.10.2 >/dev/null || fail "lc -> la (site-to-site)"
nsx a ip route show table 7347 | grep -q '192.168.30.0/24 dev dnet' || fail "a: no system route to lc's LAN"
ok "site-to-site: la <-> lc through a <-> c"

# IPv6 inside the network: every node has an address in the group's ULA /48, derived from its key
ula_c=$(nsx c ip -6 -o addr show dev dnet scope global | awk '{print $4}' | cut -d/ -f1)
case $ula_c in fd*) ;; *) fail "c has no ULA on dnet ($ula_c)" ;; esac
wait_for 10 nsx a ping -6 -c1 -W1 "$ula_c" || fail "a -> c over IPv6 inside the network"
ok "IPv6 inside the network (ULA $ula_c)"

# Exit: B's traffic to the internet goes through C (masqueraded there), while B's own DVPN
# traffic (tracker, peers) keeps using the underlay thanks to the fwmark.
masq() { nsx c nft list counter ip exitcount exited | awk '/packets/ {print $2}'; }
before=$(masq)
nsx b ping -c3 -i0.2 -W1 203.0.113.1 >/dev/null || fail "b -> internet through the exit"
[ $(( $(masq) - before )) -ge 3 ] || fail "b's internet traffic did not go through c"
nsx b ping -c2 -W1 10.10.33.1 >/dev/null || fail "b -> a broken by the exit routes"
ok "exit: b reaches the internet through c"

# B's public IPv6 address from C's prefix: C answers neighbour discovery for it on the wan
wait_for 10 nsx b ping -6 -c1 -W1 2001:db8::1 || fail "b -> internet over IPv6 through c"
nsx wan ping -6 -c3 -i0.2 -W1 2001:db8::50 >/dev/null || fail "internet -> b's public IPv6 address"
ok "public IPv6 for b via c (NDP proxy)"

# C becomes unreachable for B: B's internet moves to its second gateway, A
from=$(($(wc -l < "$W/node-b.log") + 1))
nsx b nft -f - <<NFT
table inet blockc {
    chain out { type filter hook output priority 0; ip daddr 203.0.113.20 drop; }
    chain in { type filter hook input priority 0; ip saddr 203.0.113.20 drop; }
}
NFT
# only log lines written after the block count (at start b may have used a for a moment)
wait_for 60 sh -c "tail -n +$from '$W/node-b.log' | sed 's/\x1b\[[0-9;]*m//g' | grep -q 'Exit | IPv4 via a'" \
    || fail "b did not switch its exit to a"
masq_a() { nsx a nft list counter ip exitcount exited | awk '/packets/ {print $2}'; }
before=$(masq_a)
nsx b ping -c3 -i0.2 -W1 203.0.113.1 >/dev/null || fail "b -> internet through a"
[ $(( $(masq_a) - before )) -ge 3 ] || fail "b's internet traffic did not go through a"
nsx b nft delete table inet blockc
ok "exit failover: c unreachable, b goes through a"

# Kill switch: with both gateways unreachable B's internet is blocked, not sent direct (that
# works: nat2 is right there, as "kill switch off" shows)
from=$(($(wc -l < "$W/node-b.log") + 1))
nsx b nft -f - <<NFT
table inet blockgw {
    chain out { type filter hook output priority 0; ip daddr { 203.0.113.11, 203.0.113.13, 203.0.113.20 } drop; }
    chain in { type filter hook input priority 0; ip saddr { 203.0.113.11, 203.0.113.13, 203.0.113.20 } drop; }
}
NFT
blog() { tail -n +$from "$W/node-b.log" | sed 's/\x1b\[[0-9;]*m//g'; }
wait_for 60 sh -c "tail -n +$from '$W/node-b.log' | sed 's/\x1b\[[0-9;]*m//g' | grep -q 'kill switch on'" \
    || fail "b did not turn the kill switch on"
ks=$(nsx b ping -c2 -W1 203.0.113.1 2>&1) && fail "kill switch: b's internet leaked past the tunnel"
echo "$ks" | grep -q 'From ' || fail "kill switch: no ICMP 'prohibited' for the application: $ks"
"$D" --dir "$W/b" exit --kill-switch off >/dev/null
wait_for 10 nsx b ping -c1 -W1 203.0.113.1 || fail "kill switch off: b's internet did not go direct"
"$D" --dir "$W/b" exit --kill-switch on >/dev/null
nsx b nft delete table inet blockgw
from=$(($(wc -l < "$W/node-b.log") + 1))
wait_for 60 sh -c "tail -n +$from '$W/node-b.log' | sed 's/\x1b\[[0-9;]*m//g' | grep -q 'Exit | IPv4 via'" \
    || fail "b found no gateway again"
wait_for 60 nsx b ping -c1 -W1 10.10.33.1 >/dev/null || fail "b -> a not back after the gateways came back"
wait_for 30 nsx b ping -c1 -W1 10.10.33.3 >/dev/null || fail "b -> c not back after the gateways came back"
ok "kill switch: no gateway, no internet (and direct with it off)"

# DNS through the gateway: B's DNS server forwards other names to [exit] dns, through the
# tunnel; the upstream (a stub on the "internet") sees the gateway's address, not B's.
if command -v python3 >/dev/null; then
    bg dnsup wan python3 -I -u -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("203.0.113.1", 53))
while True:
    q, a = s.recvfrom(512)
    print("from", a[0], flush=True)
    end = 12
    while q[end]:
        end += q[end] + 1
    end += 5
    s.sendto(q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:end]
             + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04" + bytes([198, 51, 100, 7]), a)
'
    "$D" --dir "$W/b" exit --dns 203.0.113.1 >/dev/null
    wait_for 15 sh -c "[ \"\$(ip netns exec b python3 -I -c '
import socket
q = b\"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01\"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, (\"10.10.33.2\", 53)); r = s.recv(512)
print(\".\".join(map(str, r[-4:])))' 2>/dev/null)\" = 198.51.100.7 ]" || fail "b's DNS did not forward example.com"
    grep -q 'from 203.0.113.20\|from 203.0.113.13\|from 203.0.113.11' "$W/dnsup.log" || fail "DNS did not go through a gateway: $(cat "$W/dnsup.log")"
    ! grep -q 'from 203.0.113.12' "$W/dnsup.log" || fail "DNS leaked from b's own address"
    "$D" --dir "$W/b" exit --dns none >/dev/null
    ok "DNS through the gateway (upstream sees the gateway, not b)"
fi

# A<->B must be a direct nat1 -> nat2 UDP flow (the tracker never forwards traffic).
nat2nat() { nsx nat1 nft list counter ip watch nat2nat | awk '/packets/ {print $2}'; }
before=$(nat2nat)
nsx a ping -c5 -i0.2 -W1 10.10.33.2 >/dev/null || fail "a -> b: packet loss"
after=$(nat2nat)
[ $((after - before)) -ge 5 ] || fail "a -> b is not a direct nat1 -> nat2 flow ($before -> $after packets)"
ok "a -> b goes directly nat1 -> nat2 ($((after - before)) packets)"

# The overlay must be encrypted and masked: a marked ICMP payload must not show up on the
# wan, peer datagrams must have no constant first byte, and equal pings must not give equal sizes.
# -Z root: distro builds of tcpdump drop to a "tcpdump" user, which is unmapped inside unshare -r
# (writing and reading the capture then fails silently).
if command -v tcpdump >/dev/null; then
    nsx wan timeout 5 tcpdump -Z root -i br0 -nn -U -w "$W/wan.pcap" udp >/dev/null 2>&1 &
    tpid=$!
    sleep 1
    nsx a ping -c30 -i0.1 -p 6476706e2d6532652d 10.10.33.2 >/dev/null || fail "a -> b during capture"
    wait $tpid || true
    # 24 bytes is the bare pcap file header
    [ "$(stat -c %s "$W/wan.pcap")" -gt 1000 ] || fail "capture is empty"
    ! grep -q dvpn-e2e- "$W/wan.pcap" || fail "plaintext overlay payload seen on the wan"
    ok "no plaintext on the wan"
    if command -v python3 >/dev/null; then
        # all UDP: sessions with the tracker are masked like the ones between nodes
        # tcpdump decodes the link layer (it differs between hosts and containers); -x prints the
        # IP packet in hex, the UDP payload starts after the IP and UDP headers.
        stats=$(tcpdump -Z root -r "$W/wan.pcap" -nn -x 'udp' 2>/dev/null | python3 -I -c '
import sys
from collections import Counter
first, sizes, pkts, cur = Counter(), Counter(), [], None
for line in sys.stdin:
    if not line.startswith((" ", "\t")):
        cur = bytearray(); pkts.append(cur); continue
    if cur is not None and ":" in line:
        cur.extend(bytes.fromhex(line.split(":", 1)[1].replace(" ", "").strip()))
for p in pkts:
    if len(p) < 29 or p[0] >> 4 != 4:
        continue
    ihl = (p[0] & 15) * 4
    first[p[ihl + 8]] += 1
    sizes[len(p)] += 1
n = sum(first.values())
print(n, first.most_common(1)[0][1] if n else 0, len(sizes))
')
        set -- $stats
        [ "${1:-0}" -ge 40 ] || fail "too few datagrams captured ($stats)"
        [ $(( $2 * 100 / $1 )) -lt 15 ] || fail "peer datagrams share a first byte too often ($2 of $1)"
        [ "$3" -ge 10 ] || fail "peer datagram sizes barely vary ($3 distinct sizes in $1 packets)"
        ok "datagrams masked on the wan: $1 packets, top first byte $2x, $3 sizes"
    fi
else
    echo "skip: tcpdump not found (plaintext check)"
fi

if command -v iperf3 >/dev/null; then
    bg iperf c iperf3 -s -1 -B 10.10.33.3
    wait_for 5 nsx c sh -c 'ss -ltn | grep -q 10.10.33.3:5201' || fail "iperf3 server did not start"
    nsx a iperf3 -c 10.10.33.3 -t 3 -f m > "$W/iperf.out" 2>&1 || fail "iperf3 a -> c: $(tail -n 3 "$W/iperf.out")"
    ok "iperf3 a -> c: $(awk '/receiver/ {print $7, $8}' "$W/iperf.out")"
else
    echo "skip: iperf3 not found"
fi

# Invites are one-time: once the admin node (A) sees B and C online, it issues them regular
# certificates (which they save) and revokes the join keys.
renewed() { ! "$D" --dir "$W/$1" group list | grep -q '(invite)'; }
for n in b c; do wait_for 30 renewed $n || fail "$n still has its invite certificate"; done
"$D" --dir "$W/a" group members | grep -q 'b .*10.10.33.2' || fail "a: b missing from group members"
ok "invite certificates replaced by regular ones"

# The admin changes members on the fly (new certificates in the group records): C gets one more
# subnet, B a new address; everybody follows within seconds, B moves the address on its TUN.
"$D" --dir "$W/a" node set c --add-route 192.168.31.0/24 >/dev/null || fail "node set c"
"$D" --dir "$W/a" node set b --addr 10.10.33.22 >/dev/null || fail "node set b"
wait_for 30 sh -c "ip netns exec b ip route show table 7347 | grep -q '192.168.31.0/24 dev dnet'" \
    || fail "b did not learn c's new subnet"
wait_for 30 sh -c "ip netns exec b ip -4 addr show dnet | grep -q 10.10.33.22" || fail "b did not take its new address"
wait_for 20 nsx a ping -c1 -W1 10.10.33.22 || fail "a -> b at its new address"
"$D" --dir "$W/a" node list | grep -q '| b .*10.10.33.22' || fail "node list does not show b's new address"
"$D" --dir "$W/a" node set b --addr 10.10.33.2 >/dev/null || fail "node set b back"
wait_for 30 sh -c "ip netns exec b ip -4 addr show dnet | grep -q '10.10.33.2/'" || fail "b did not take its address back"
wait_for 20 nsx a ping -c1 -W1 10.10.33.2 || fail "a -> b at its old address again"
ok "node set: new subnet for c and a new address for b reach everybody"

# ACL: the admin forbids ping from B to C; C enforces it (nftables on its TUN), A still pings C.
cat > "$W/acl.toml" <<'TOML'
default = "allow"
[[rule]]
from = ["b"]
to = ["c"]
proto = "icmp"
action = "deny"
TOML
"$D" --dir "$W/a" acl set "$W/acl.toml" >/dev/null || fail "acl set"
wait_for 20 sh -c "ip netns exec c nft list table inet dvpn_acl >/dev/null 2>&1" || fail "c did not install the ACL"
! nsx b ping -c2 -W1 10.10.33.3 >/dev/null 2>&1 || fail "ACL deny did not block b -> c"
nsx a ping -c2 -W1 10.10.33.3 >/dev/null || fail "ACL blocked a -> c too"
"$D" --dir "$W/a" acl show | grep -q 'action = "deny"' || fail "acl show"
"$D" --dir "$W/a" acl clear >/dev/null || fail "acl clear"
wait_for 20 nsx b ping -c1 -W1 10.10.33.3 || fail "b -> c still blocked after acl clear"
ok "ACL: ping b -> c denied, a -> c allowed, cleared again"

# Names of members: every node answers DNS for <name>.dvpn and <name>.<group>.dvpn on its
# overlay address (systemd-resolved would send *.dvpn there; here we ask it directly).
if command -v python3 >/dev/null; then
    dnsq() { # dnsq NS SERVER NAME: the first A record, fails on none
        nsx "$1" python3 -I -c '
import socket, sys
srv, name = sys.argv[1], sys.argv[2]
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(q, (srv, 53))
r = s.recv(512)
if r[7] == 0:
    sys.exit(1)
print(".".join(map(str, r[-4:])))
' "$2" "$3"
    }
    [ "$(dnsq a 10.10.33.3 b.dvpn)" = "10.10.33.2" ] || fail "c's DNS: b.dvpn"
    [ "$(dnsq a 10.10.33.3 B.e2e.dvpn)" = "10.10.33.2" ] || fail "c's DNS: B.e2e.dvpn"
    [ "$(dnsq b 10.10.33.2 c.dvpn)" = "10.10.33.3" ] || fail "b's DNS: c.dvpn"
    ! dnsq a 10.10.33.3 nobody.dvpn >/dev/null 2>&1 || fail "c's DNS answered for an unknown name"
    ok "DNS: members by name (b.dvpn, b.e2e.dvpn)"
    # mDNS: what the system's resolver (avahi, systemd-resolved) asks for <name>.local on the
    # tunnel interface is answered by the node
    mdnsq() { # mdnsq NS OWN_ADDR NAME: the A record from the mDNS answer
        nsx "$1" python3 -I -c '
import socket, struct, sys
own, name = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", 5353))
s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton("224.0.0.251") + socket.inet_aton(own))
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(own))
s.settimeout(3)
q = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00\x00\x01\x00\x01"
s.sendto(q, ("224.0.0.251", 5353))
while True:
    r, _ = s.recvfrom(512)
    if r[2] & 0x80 and r[7] > 0:
        print(".".join(map(str, r[-4:])))
        break
' "$2" "$3"
    }
    [ "$(mdnsq a 10.10.33.1 c.local)" = "10.10.33.3" ] || fail "mDNS: c.local from a"
    ok "mDNS: members as <name>.local"
fi

# Revocation (before the roaming check, which leaves A without a tracker session for a
# while): the admin revokes B with the CLI while its node runs; the node spreads the record
# (tracker + direct), C drops B and B can no longer reach anybody.
"$D" --dir "$W/a" group revoke b --in 6 >/dev/null || fail "group revoke"
wait_for 20 grep -q 'revoked, dropped' "$W/node-c.log" || fail "c did not drop revoked b"
wait_for 20 grep -q 'this node is revoked' "$W/node-b.log" || fail "b did not learn it is revoked"
! nsx c ping -c2 -W1 10.10.33.2 >/dev/null 2>&1 || fail "c still reaches revoked b"
! nsx b ping -c2 -W1 10.10.33.1 >/dev/null 2>&1 || fail "revoked b still reaches a"
nsx a ping -c2 -W1 10.10.33.3 >/dev/null || fail "a -> c broken by the revocation"
ok "revoked b is cut off, a <-> c unaffected"

# The revocation also changed the group psk (sealed to A and C only), switching 6 s later;
# A and C keep talking across the switch, B does not get the new psk.
for n in a c; do
    wait_for 20 grep -q 'psk epoch 1 active' "$W/node-$n.log" || fail "$n did not switch to psk epoch 1"
done
grep -q '^epoch = 1' c/config.toml || fail "c did not save the new psk epoch"
grep -q '^epoch = 0' b/config.toml || fail "revoked b got the new psk"
sleep 1
nsx a ping -c3 -i0.2 -W1 10.10.33.3 >/dev/null || fail "a -> c lost after the psk change"
nsx c ping -c3 -i0.2 -W1 10.10.33.1 >/dev/null || fail "c -> a lost after the psk change"
ok "psk changed after the revocation, a <-> c unaffected"

# Roaming: nat1 gets a new public address, so A's packets suddenly come from elsewhere
# (removing the address also drops nat1's masquerade mappings). C must follow A to the new
# endpoint on the first authenticated packet, without waiting for the tracker.
nsx nat1 ip addr add 203.0.113.13/24 dev wan0
nsx nat1 ip addr del 203.0.113.11/24 dev wan0
wait_for 10 nsx a ping -c1 -W1 10.10.33.3 || fail "a -> c lost after nat1 changed its address"
grep -q 'at new endpoint 203.0.113.13:' "$W/node-c.log" || fail "c did not roam to a's new endpoint"
nsx a ping -c3 -i0.2 -W1 10.10.33.3 >/dev/null || fail "a -> c: packet loss after roaming"
ok "a <-> c survives a NAT address change (roaming)"
# the tracker session is found by its index, not the address: it follows A too
wait_for 20 grep -q 'moved 203.0.113.11:.* -> 203.0.113.13:' "$W/tracker.log" || fail "tracker did not follow a's new address"
ok "tracker session survives the NAT address change"

# ---- static peers, no tracker ---------------------------------------------------------
# Everything is stopped; a new group whose admin S1 (on C's public address, fixed port) invites
# S2 (behind nat1) with --static: S2 connects straight to S1, no tracker exists any more.
cleanup
PIDS=""
# a clean stop (SIGTERM) removed the routing rules and table again
! nsx a ip rule | grep -q 7347 || fail "a left its routing rules behind"
[ -z "$(nsx c ip route show table 7347)" ] || fail "c left its routing table behind"
! nsx c nft list tables | grep -q dvpn_gw || fail "gateway c left its NAT table behind"
[ -z "$(nsx c ip -6 neigh show proxy)" ] || fail "gateway c left NDP proxies behind"
mkdir s1 s2
"$D" --dir "$W/s1" show-key >/dev/null 2>&1
sed -i 's/^bind_port = .*/bind_port = "7000"/' s1/config.toml
"$D" --dir "$W/s1" group create solo -a 10.10.44.1 -n s1 >/dev/null || fail "s1: group create"
inv=$("$D" --dir "$W/s1" group invite -n s2 -a 10.10.44.2 --static 203.0.113.20:7000 2>/dev/null) || fail "s1: invite"
"$D" --dir "$W/s2" group join "$inv" >/dev/null 2>&1 || fail "s2: join"
grep -q '^\[\[static_peers\]\]' s2/config.toml || fail "s2: no [[static_peers]] from the invite"
! grep -q '^\[servers' s2/config.toml || fail "s2 has a tracker configured"
bg node-s1 c "$D" --dir "$W/s1" -a 127.0.0.1:9902
bg node-s2 a "$D" --dir "$W/s2" -a 127.0.0.1:9902
for n in a c; do wait_for 10 nsx $n ip -4 addr show dnet || fail "static: no tun in $n"; done
reach a s1 10.10.44.1
reach c s2 10.10.44.2
ok "connected by a static address, without a tracker"

# ---- pure IPv6 ------------------------------------------------------------------------
# Two new namespaces with IPv6 only (no IPv4 address at all) on the wan, a tracker on its
# IPv6 address (the same dual-stack socket also serves IPv4): X6 creates a group, Y6 joins by
# invite, they find each other through the tracker and talk over IPv6.
cleanup
PIDS=""
for n in x6 y6; do ip netns add $n; nsx $n ip link set lo up; done
wan_port6() { # wan_port6 NS ADDR
    ip link add "w-$1" type veth peer name wan0
    ip link set wan0 netns "$1"
    ip link set "w-$1" netns wan
    nsx wan ip link set "w-$1" master br0 up
    nsx "$1" ip -6 addr add "$2/64" dev wan0 nodad
    nsx "$1" ip link set wan0 up
}
wan_port6 x6 2001:db8::11
wan_port6 y6 2001:db8::12
! nsx x6 ip -4 addr show scope global | grep -q inet || fail "x6 has an IPv4 address"
bg tracker6 wan "$D" --dir "$W/trk" server -p 6485
TRACKER6=$!
wait_for 10 grep -q 'Server started' tracker6.log || fail "tracker did not start on ::"
mkdir x6 y6
"$D" --dir "$W/x6" show-key >/dev/null 2>&1
cat >> x6/config.toml <<TOML

[servers.v6]
addr = "2001:db8::1"
port = 6485
key = "$TKEY"
TOML
"$D" --dir "$W/x6" group create six -a 10.10.66.1 -n x6 >/dev/null || fail "x6: group create"
inv=$("$D" --dir "$W/x6" group invite -n y6 -a 10.10.66.2 2>/dev/null) || fail "x6: invite"
"$D" --dir "$W/y6" group join "$inv" >/dev/null 2>&1 || fail "y6: join"
bg node-x6 x6 "$D" --dir "$W/x6" -a 127.0.0.1:9902
bg node-y6 y6 "$D" --dir "$W/y6" -a 127.0.0.1:9902
reach x6 y6 10.10.66.2
reach y6 x6 10.10.66.1
grep -q 'new endpoint \[2001:db8::12\]' "$W/node-x6.log" || fail "x6 did not get y6's IPv6 endpoint"
ok "pure IPv6: tracker, discovery and the tunnel over IPv6"

# ---- mesh: relays ---------------------------------------------------------------------
# MA and MC cannot reach each other (a filter on MA, like a hostile network between them);
# MB and MD are relays. MA <-> MC must work through a relay, survive that relay going down
# (the other one takes over), and move to the direct path once it opens.
for n in ma mb mc md; do ip netns add $n; nsx $n ip link set lo up; done
wan_port ma 203.0.113.31
wan_port mb 203.0.113.32
wan_port mc 203.0.113.33
wan_port md 203.0.113.34
nsx ma nft -f - <<NFT
table inet block {
    chain out { type filter hook output priority 0; ip daddr 203.0.113.33 drop; }
    chain in { type filter hook input priority 0; ip saddr 203.0.113.33 drop; }
}
NFT
mkdir ma mb mc md
"$D" --dir "$W/ma" show-key >/dev/null 2>&1
cat >> ma/config.toml <<TOML

[servers.main]
addr = "203.0.113.1"
port = 6485
key = "$TKEY"
TOML
"$D" --dir "$W/ma" group create mesh -a 10.10.77.1 -n ma >/dev/null || fail "ma: group create"
for x in "mb 2 --relay" "mc 3" "md 4 --relay"; do
    set -- $x
    inv=$("$D" --dir "$W/ma" group invite -n "$1" -a "10.10.77.$2" ${3:-} 2>/dev/null) || fail "invite $1"
    "$D" --dir "$W/$1" group join "$inv" >/dev/null 2>&1 || fail "$1: join"
done
sed -i 's/^mtu = .*/mtu = 1420/' ma/config.toml
for n in ma mb mc md; do bg "node-$n" $n "$D" --dir "$W/$n" -a 127.0.0.1:9902; done
reach ma mc 10.10.77.3
reach mc ma 10.10.77.1
plain() { sed 's/\x1b\[[0-9;]*m//g' "$W/node-$1.log"; } # logs are coloured
plain ma | grep -q 'end-to-end session with mc' || plain mc | grep -q 'end-to-end session with ma' \
    || fail "ma <-> mc did not go through a relay"
via=$( (plain ma; plain mc) | sed -n 's/.*end-to-end session with [^ ]* via \(m[bd]\).*/\1/p' | tail -n1)
ok "ma <-> mc through relay $via"

# traceroute through the mesh: a relay shows up as a hop (by its overlay address), as an
# ordinary router would; the end node lowers the TTL by the relays passed. Both relays are
# equally good, so the one in use is taken from the trace, not from when the session started.
if command -v tracepath >/dev/null; then
    tp=$(nsx ma tracepath -n -m 5 10.10.77.3 2>&1 || true)
    # the first hop that is not the target (path MTU discovery may put a line first)
    hop=$(echo "$tp" | awk '$1 == "1:" && $2 != "10.10.77.3" {print $2; exit}')
    case $hop in 10.10.77.2) via=mb ;; 10.10.77.4) via=md ;; *) fail "tracepath ma -> mc shows no relay: $tp" ;; esac
    echo "$tp" | grep -q 'reached' || fail "tracepath ma -> mc did not reach mc: $tp"
    ula() { nsx "$1" ip -6 -o addr show dev dnet scope global | awk '{print $4}' | cut -d/ -f1; }
    tp6=$(nsx ma tracepath -6 -n -m 5 "$(ula mc)" 2>&1 || true)
    hop6=$(echo "$tp6" | awk -v t="$(ula mc)" '$1 == "1:" && $2 != t {print $2; exit}')
    [ "$hop6" = "$(ula mb)" ] || [ "$hop6" = "$(ula md)" ] || fail "tracepath -6 ma -> mc shows no relay: $tp6"
    ok "traceroute shows relay $via (IPv4 and IPv6)"
else
    echo "skip: tracepath not found (traceroute through relays)"
fi

# diagnostics from the running node (through its API)
dv() { n=$1; shift; nsx "$n" "$D" --dir "$W/$n" -a 127.0.0.1:9902 "$@"; }
p=$(dv ma path mc 2>&1) || fail "path: $p"
echo "$p" | grep -q " -> $via -> mc" || fail "path ma -> mc does not go through $via: $p"
dv ma status 2>&1 | grep -q 'group' || fail "status"
dv ma neighbors 2>&1 | grep -q "| $via " || fail "neighbors of ma do not list $via"
dv ma routes 2>&1 | grep -q "| mc .*| $via " || fail "routes of ma: mc not via $via"
pg=$(dv ma ping mc -c 2 2>&1) || fail "dvpn ping: $pg"
echo "$pg" | grep -q 'ms (relays)' || fail "dvpn ping ma -> mc not through relays: $pg"
ok "diagnostics: dvpn path / status / neighbors / routes / ping"

# Path MTU through relays: MA's TUN takes 1420-byte packets, a relayed path carries 1368;
# a too big packet with DF set gets "fragmentation needed" from MA itself, smaller ones pass
out=$( (nsx ma ping -c1 -W1 -M do -s 1392 10.10.77.3 || true; nsx ma ping -c1 -W1 -M do -s 1392 10.10.77.3 || true) 2>&1)
# the kernel learned the path MTU from that ICMP (ping may only say "message too long")
nsx ma ip route get 10.10.77.3 | grep -q 'mtu 1368' || fail "no path MTU 1368 for ma -> mc through relays: $out $(nsx ma ip route get 10.10.77.3)"
nsx ma ping -c1 -W2 -M do -s 1300 10.10.77.3 >/dev/null || fail "ma -> mc: a packet that fits did not pass"
ok "path MTU through relays: fragmentation needed, mtu 1368"

# the relay in use goes down: the other one takes over
case $via in mb) other=md ;; *) other=mb ;; esac
nsx "$via" ip link set wan0 down
wait_for 60 nsx ma ping -c1 -W1 10.10.77.3 || fail "ma -> mc lost after $via went down"
nsx ma ping -c3 -i0.2 -W1 10.10.77.3 >/dev/null || fail "ma -> mc unstable through $other"
ok "relay $via down: ma <-> mc through $other"
nsx "$via" ip link set wan0 up

# the direct path opens: traffic moves to it
nsx ma nft delete table inet block
nsx ma nft -f - <<NFT
table ip direct {
    counter c { }
    chain out { type filter hook output priority 0; ip daddr 203.0.113.33 meta l4proto udp counter name c; }
}
NFT
direct() { nsx ma nft list counter ip direct c | awk '/packets/ {print $2}'; }
wait_for 40 sh -c "ip netns exec ma ping -c1 -W1 10.10.77.3 >/dev/null && [ \$(ip netns exec ma nft list counter ip direct c | awk '/packets/ {print \$2}') -gt 0 ]" \
    || fail "no direct packets to mc after the path opened"
before=$(direct)
nsx ma ping -c5 -i0.2 -W1 10.10.77.3 >/dev/null || fail "ma -> mc after the path opened"
[ $(( $(direct) - before )) -ge 5 ] || fail "ma -> mc still not direct"
ok "direct path opened: ma <-> mc go direct"

# Without a tracker: it goes away, the admin changes a member, the record still reaches
# everybody through the neighbours (STATE between link sessions)
kill "$TRACKER6"
"$D" --dir "$W/ma" node set mc --add-route 192.168.77.0/24 >/dev/null || fail "ma: node set without tracker"
wait_for 40 sh -c "ip netns exec mb ip route show table 7347 | grep -q '192.168.77.0/24 dev dnet'" \
    || fail "mb did not get mc's new subnet without a tracker"
wait_for 10 sh -c "ip netns exec md ip route show table 7347 | grep -q '192.168.77.0/24 dev dnet'" \
    || fail "md did not get mc's new subnet without a tracker"
ok "without a tracker: a member change reaches everybody through the neighbours"

echo "PASS"
