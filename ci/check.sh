#!/usr/bin/env bash
# The baseline gate, runnable with no GitHub in the loop. Run before every
# push/merge; .github/workflows/ci.yml runs the same jobs on every push once
# the commit reaches the remote. Any failure fails the gate (set -e).
#
# The hosted gate pins the Zig version to `minimum_zig_version` in
# build.zig.zon; locally, run against the same version (`zig version`) or a
# hosted red on an unrelated stdlib move is indistinguishable from a
# regression here.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== fmt =="
zig fmt --check src build.zig

echo "== build + test (Debug) =="
zig build
zig build test

# Release modes exercise different code: safety checks are removed in
# ReleaseFast, and the store's internal invariants are expressed as
# assertions. Both must build and pass.
for mode in ReleaseSafe ReleaseFast; do
  echo "== build + test ($mode) =="
  zig build -Doptimize="$mode"
  zig build test -Doptimize="$mode"
done

echo "== WAL sync probe (the real syscalls, not just seam events) =="
# The unit suite observes the writer's durability seam EVENTS; this step is the
# discriminator that the syscalls behind them still happen (B2p1 review,
# blocking finding 3). The probe (src/store/wal_sync_probe.zig) drives a fixed
# scenario — create segment, three appends, a rollover, one more append — and
# the kernel-observed sync sequence is pinned exactly:
#   create seg 1 (file fsync, dir fsync) . 3 appends (fdatasync each) .
#   rollover seal (fsync) . create seg 2 (file fsync, dir fsync) .
#   final append (fdatasync)
# Deleting either of the writer's syncs, or swapping one flavour for the other,
# changes this sequence. strace is required locally; if it is genuinely absent,
# the step is skipped LOUDLY and the gate cannot claim the discriminator ran.
if command -v strace >/dev/null 2>&1; then
  zig build sync-probe
  probe_trace="$(mktemp)"
  strace -e trace=fsync,fdatasync -o "$probe_trace" ./zig-out/bin/wal-sync-probe
  got="$(grep -oE '^(fsync|fdatasync)' "$probe_trace" | tr '\n' ' ')"
  rm -f "$probe_trace"
  want="fsync fsync fdatasync fdatasync fdatasync fsync fsync fsync fdatasync "
  if [ "$got" != "$want" ]; then
    echo "sync probe MISMATCH:"
    echo "  want: $want"
    echo "  got:  $got"
    exit 1
  fi
else
  echo "SKIPPED: strace not installed — the sync-site discriminator DID NOT run"
fi

echo "== package (.paths allowlist covers what a consumer is entitled to) =="
for f in README.md NOTICE.md LICENSE-EPL-1.0.txt LICENSE-EDL-1.0.txt; do
  grep -q "\"$f\"" build.zig.zon || { echo "not in build.zig.zon .paths: $f"; exit 1; }
  test -f "$f" || { echo "listed in .paths but missing on disk: $f"; exit 1; }
done

echo "== gate PASSED =="
