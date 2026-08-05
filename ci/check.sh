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
#   final append (fdatasync) . 'K' mark append (fdatasync — a TAG-conditional
#   skip of the mark's force is invisible to a section-only scenario; B3
#   review, blocking finding 1)
# Deleting either of the writer's syncs, or swapping one flavour for the other,
# changes this sequence. strace is REQUIRED: a gate that skips this step passes
# on seam events alone, which is the exact defect the step exists to catch
# (B2p1 r2 review, blocking finding 1).
#
# The trace is taken with `-y`, so each call carries the PATH of the descriptor
# it ran on, and the pin is a sequence of `call:file` pairs rather than bare
# syscall names. A name-only pin says a sync happened, not what it synced: a
# force that reported the active segment while syncing a stale one produced a
# byte-identical name-only trace (B3 r2 review, blocking finding 1). The
# temp directory's own name carries the pid, so it normalises to `DIR`; the
# segment names are `<base>.wal.<16 hex>` and are pinned literally.
command -v strace >/dev/null 2>&1 || {
  echo "strace not installed — the sync-site discriminator cannot run; gate FAILED"
  exit 1
}
zig build sync-probe
probe_trace="$(mktemp)"
strace -y -e trace=fsync,fdatasync -o "$probe_trace" ./zig-out/bin/wal-sync-probe
got="$(awk 'match($0, /^(fsync|fdatasync)\([0-9]+<[^>]+>/) {
  call = substr($0, 1, index($0, "(") - 1)
  rest = substr($0, index($0, "<") + 1)
  path = substr(rest, 1, index(rest, ">") - 1)
  n = split(path, parts, "/")
  name = parts[n]
  if (name ~ /^mapdb5_syncprobe_[0-9]+$/) name = "DIR"
  printf "%s:%s ", call, name
}' "$probe_trace")"
rm -f "$probe_trace"
want="fsync:store.db.wal.0000000000000001 fsync:DIR fdatasync:store.db.wal.0000000000000001 fdatasync:store.db.wal.0000000000000001 fdatasync:store.db.wal.0000000000000001 fsync:store.db.wal.0000000000000001 fsync:store.db.wal.0000000000000002 fsync:DIR fdatasync:store.db.wal.0000000000000002 fdatasync:store.db.wal.0000000000000002 "
if [ "$got" != "$want" ]; then
  echo "sync probe MISMATCH:"
  echo "  want: $want"
  echo "  got:  $got"
  exit 1
fi

echo "== WAL v3 fixture generator: two PROCESSES, byte for byte (C2z) =="
# Contract §5.4 obligation 8's across-process half. The generator compares two
# runs of each shape inside one process and refuses to publish otherwise, and
# the unit suite compares two in-process `generate` calls over the whole tree —
# but both live in one process and share every process-wide seed, so an output
# depending on an address, a hash-map iteration order or a lazily initialised
# global agrees with itself and still differs between runs. `fragment.tsv` is
# also the one file the generator structurally cannot compare: it does not
# exist yet when `produceTwice` runs.
#
# Two real invocations of the documented CLI, whole trees diffed. `--commit` is
# passed the same value both times deliberately: it is metadata the sync script
# supplies, not something the generator derives, and letting it vary here would
# make the comparison fail for a reason that is not about determinism.
a="$(mktemp -d)"; b="$(mktemp -d)"
trap 'rm -rf "$a" "$b"' EXIT
zig build fixtures -- --wal3 "$a" --force --commit ci >/dev/null
zig build fixtures -- --wal3 "$b" --force --commit ci >/dev/null
if ! diff -r "$a" "$b" >/dev/null; then
  echo "the WAL v3 fixture generator is NOT deterministic across two processes:"
  diff -r "$a" "$b" || true
  exit 1
fi
# ...and non-vacuously: an empty tree diffs clean against another empty tree.
for want in wal3-zig-tail wal3-zig-cleaned fragment.tsv layout.tsv; do
  test -e "$a/$want" || { echo "generator published no $want"; exit 1; }
done

echo "== package (.paths allowlist covers what a consumer is entitled to) =="
for f in README.md NOTICE.md LICENSE-EPL-1.0.txt LICENSE-EDL-1.0.txt; do
  grep -q "\"$f\"" build.zig.zon || { echo "not in build.zig.zon .paths: $f"; exit 1; }
  test -f "$f" || { echo "listed in .paths but missing on disk: $f"; exit 1; }
done

echo "== gate PASSED =="
