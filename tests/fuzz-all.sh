#!/bin/sh
# Runs every cargo-fuzz target for SECONDS, all at once (one core each, at most JOBS at a time),
# with the corpus in fuzz/corpus/<target>. On a crash prints the target's log tail and the
# crashing input (base64) and exits non-zero.
#
#   tests/fuzz-all.sh 60            # CI on every push
#   JOBS=4 tests/fuzz-all.sh 600    # long run
set -eu
SECONDS_PER_TARGET=${1:-60}
JOBS=${JOBS:-$(nproc)}
cd "$(dirname "$0")/../fuzz"
LOGS=$(mktemp -d)
trap 'rm -rf "$LOGS"' EXIT

targets=$(cargo +nightly fuzz list)
running=0
for t in $targets; do
    mkdir -p "corpus/$t"
    ( cargo +nightly fuzz run "$t" -- -max_total_time="$SECONDS_PER_TARGET" >"$LOGS/$t.log" 2>&1 \
        && echo ok >"$LOGS/$t.rc" || echo fail >"$LOGS/$t.rc" ) &
    running=$((running + 1))
    if [ "$running" -ge "$JOBS" ]; then wait; running=0; fi
done
wait

rc=0
for t in $targets; do
    if [ "$(cat "$LOGS/$t.rc")" = ok ]; then
        echo "ok: $t: $(grep -o 'Done [0-9]* runs' "$LOGS/$t.log" | tail -n1), corpus $(ls "corpus/$t" | wc -l)"
    else
        rc=1
        echo "FAIL: $t"
        tail -n 40 "$LOGS/$t.log"
        for f in artifacts/"$t"/*; do
            [ -f "$f" ] && echo "input $f (base64): $(base64 -w0 "$f")"
        done
    fi
done
exit "$rc"
