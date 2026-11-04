#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
build_dir=${BUILD_DIRECTORY:-$repo/.build/linux}
jobs=${BUILD_JOBS:-$(nproc)}
qmake_args=()
[[ ${COVERAGE:-0} == 1 ]] && qmake_args+=(CONFIG+=coverage)
mkdir -p "$build_dir/app" "$build_dir/tests"
cd "$build_dir/app"
qmake6 "$repo/STIGQter.pro" "${qmake_args[@]}"
if [[ -n ${BUILD_WRAPPER:-} ]]; then
  "$BUILD_WRAPPER" --out-dir "$repo/.build/bw-output" make -j"$jobs"
else
  make -j"$jobs"
fi
if [[ ${1:-} != --app-only ]]; then
  cd "$build_dir/tests"
  qmake6 "$repo/tests/tests.pro" "${qmake_args[@]}"
  make -j"$jobs"
fi
