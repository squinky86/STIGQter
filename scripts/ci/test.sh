#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
binary=${1:-$repo/.build/linux/tests/tst_stigqter}
binary=$(realpath "$binary")
test_runtime=$(mktemp -d -t stigqter-test-XXXXXXXX)
trap 'rm -rf -- "$test_runtime"' EXIT
mkdir -p "$test_runtime/tests" "$repo/.build/results"
for fixture in U_ASD_V5R1_STIG.zip U_ASD_V5R2_STIG.zip emassTRImport.xlsx xccdf_lol.xml; do
  cp "$repo/tests/$fixture" "$test_runtime/tests/"
done
export XDG_DATA_HOME="$test_runtime/data" XDG_CONFIG_HOME="$test_runtime/config" XDG_CACHE_HOME="$test_runtime/cache"
cd "$test_runtime"
runner=()
if command -v xvfb-run >/dev/null; then runner=(xvfb-run -a); else export QT_QPA_PLATFORM=offscreen; fi
"${runner[@]}" "$binary" -o "$repo/.build/results/tests.txt",txt -o "$repo/.build/results/tests.xml",junitxml
