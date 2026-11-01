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
# Needs: unshare, ip, nft, ping; optional: iperf3 (throughput), tcpdump (plaintext check).
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
"$D" --dir "$W/a" group create e2e -a 10.10.33.1 -n a >/dev/null || fail "group create"
join() { # join NAME ADDR
    inv=$("$D" --dir "$W/a" group invite -n "$1" -a "$2" 2>/dev/null) || fail "invite for $1"
    "$D" --dir "$W/$1" group join "$inv" >/dev/null || fail "$1 could not join"
    grep -q '203.0.113.1' "$1/config.toml" || fail "$1: the invite did not add the tracker"
}
join b 10.10.33.2
join c 10.10.33.3
"$D" --dir "$W/b" group list | grep -q 'e2e.*member.*10.10.33.2' || fail "b: group list"
# All namespaces share one /run, so the default unix API socket would collide: use UDP
# on each namespace's own loopback instead.
for n in a b c; do bg "node-$n" $n "$D" --dir "$W/$n" -a 127.0.0.1:9902; done
for n in a b c; do
    wait_for 10 nsx $n ip -4 addr show dnet || fail "node $n: no tun interface"
done
ok "nodes up"

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
nsx wan ip -6 addr add 2001:db8::1/64 dev br0 nodad
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

echo "PASS"
