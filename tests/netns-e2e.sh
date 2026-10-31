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
# Overlay: A 10.10.33.1, B 10.10.33.2, C 10.10.33.3, all links encrypted.
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

# ---- nodes ----------------------------------------------------------------------------
# setup NAME OVERLAY_ADDR: config with the tracker and the group psk, own address, export own record.
# Every command gets --dir, otherwise dvpn would write config.toml next to the binary.
PSK=$("$D" --dir "$W/trk" gen-key)
setup() {
    mkdir "$1"
    "$D" --dir "$W/$1" list >/dev/null
    cat >> "$1/config.toml" <<TOML

[servers.main]
addr = "203.0.113.1"
port = 6485
key = "$TKEY"

[group]
psk = "$PSK"
TOML
    key=$("$D" --dir "$W/$1" show-key)
    [ ${#key} -eq 43 ] || fail "$1: show-key printed '$key', want a 43-char key"
    "$D" --dir "$W/$1" set -p "$key" -n "$1" -a "$2" >/dev/null
    "$D" --dir "$W/$1" export-peer -o "$W/$1.peer"
}
setup a 10.10.33.1
setup b 10.10.33.2
setup c 10.10.33.3
for n in a b c; do
    for p in a b c; do [ $n = $p ] || "$D" --dir "$W/$n" import-peer -i "$W/$p.peer" >/dev/null; done
done
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

# The overlay must be encrypted: a marked ICMP payload must not show up on the wan.
if command -v tcpdump >/dev/null; then
    nsx wan timeout 4 tcpdump -i br0 -nn -U -w "$W/wan.pcap" udp >/dev/null 2>&1 &
    tpid=$!
    sleep 1
    nsx a ping -c3 -i0.2 -p 6476706e2d6532652d 10.10.33.2 >/dev/null || fail "a -> b during capture"
    wait $tpid || true
    [ -s "$W/wan.pcap" ] || fail "capture is empty"
    ! grep -q dvpn-e2e- "$W/wan.pcap" || fail "plaintext overlay payload seen on the wan"
    ok "no plaintext on the wan"
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

# Roaming: nat1 gets a new public address, so A's packets suddenly come from elsewhere
# (removing the address also drops nat1's masquerade mappings). C must follow A to the new
# endpoint on the first authenticated packet, without waiting for the tracker.
nsx nat1 ip addr add 203.0.113.13/24 dev wan0
nsx nat1 ip addr del 203.0.113.11/24 dev wan0
wait_for 10 nsx a ping -c1 -W1 10.10.33.3 || fail "a -> c lost after nat1 changed its address"
grep -q 'at new endpoint 203.0.113.13:' "$W/node-c.log" || fail "c did not roam to a's new endpoint"
nsx a ping -c3 -i0.2 -W1 10.10.33.3 >/dev/null || fail "a -> c: packet loss after roaming"
ok "a <-> c survives a NAT address change (roaming)"

echo "PASS"
