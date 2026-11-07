#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
work=${WINDOWS_BUILD_DIRECTORY:-$repo/.build/windows}
prefix=${WINDOWS_TOOLCHAIN_DIRECTORY:-$repo/.build/toolchain}
mkdir -p "$work/tests"
cd "$work/tests"
"$prefix/host/bin/qmake" -qtconf "$prefix/target/bin/target_qt.conf" "$repo/tests/tests.pro" \
  "STIGQTER_STATIC_DEPS=$prefix/deps" CONFIG+=release \
  'QMAKE_LFLAGS_RELEASE+=-Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va -Wl,--no-insert-timestamp'
make -j"${BUILD_JOBS:-$(nproc)}"
x86_64-w64-mingw32-strip --strip-all --preserve-dates release/tst_stigqter.exe
python3 "$repo/scripts/ci/verify-windows.py" release/tst_stigqter.exe
