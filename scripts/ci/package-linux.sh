#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
version=$(cat VERSION)
package_work=${PACKAGE_BUILD_DIRECTORY:-$repo/.build/package}
mkdir -p "$package_work" .build/dist
# Build from the reviewed working tree locally and the exact checked-out tag in CI.
# Copy tracked and new source files, excluding generated build output via .gitignore.
python3 - "$package_work/source" <<'PY'
from pathlib import Path
import shutil, subprocess, sys
destination = Path(sys.argv[1])
if destination.exists(): shutil.rmtree(destination)
destination.mkdir(parents=True)
paths = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z']).split(b'\0')
tracked_modes = {}
for entry in subprocess.check_output(['git', 'ls-files', '--stage', '-z']).split(b'\0'):
    if entry:
        info, name = entry.split(b'\t', 1)
        tracked_modes[name.decode()] = int(info.split()[0], 8) & 0o777
for raw in paths:
    if not raw: continue
    source = Path(raw.decode())
    if not source.is_file(): continue
    target = destination / source
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    mode = tracked_modes.get(str(source), 0o755 if source.read_bytes().startswith(b'#!') else 0o644)
    target.chmod(0o755 if str(source) == 'debian/rules' else mode)
PY
# Capture sources before packaging creates Makefiles, objects or binaries.
tar -czf ".build/dist/STIGQter-${version}-source.tar.gz" -C "$package_work" source
cd "$package_work/source"
dpkg_args=(--no-sign --build=binary)
# Local unprivileged validation may provide debhelper via PATH/PERL5LIB.
# Hosted CI always checks the installed package dependencies.
[[ ${LOCAL_UNPRIVILEGED_PACKAGE:-0} == 1 ]] && dpkg_args+=(-d)
dpkg-buildpackage "${dpkg_args[@]}"
cd "$repo"
for package in "$package_work"/*.deb; do
  arch=$(dpkg-deb -f "$package" Architecture)
  cp "$package" ".build/dist/STIGQter-${version}-ubuntu26.04-${arch}.deb"
done
cd .build/dist
sha256sum ./*.deb ./*-source.tar.gz > SHA256SUMS-linux.txt
