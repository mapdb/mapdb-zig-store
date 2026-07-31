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

echo "== package (.paths allowlist covers what a consumer is entitled to) =="
for f in README.md NOTICE.md LICENSE-EPL-1.0.txt LICENSE-EDL-1.0.txt; do
  grep -q "\"$f\"" build.zig.zon || { echo "not in build.zig.zon .paths: $f"; exit 1; }
  test -f "$f" || { echo "listed in .paths but missing on disk: $f"; exit 1; }
done

echo "== gate PASSED =="
