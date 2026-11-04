#!/usr/bin/env bash
set -euo pipefail
mode=${1:-linux}
packages=(build-essential ca-certificates openssl git python3 cmake ninja-build pkg-config zip unzip)
case "$mode" in
  linux)
    packages+=(qt6-base-dev qt6-base-dev-tools qmake6 libqt6sql6-sqlite libzip-dev
      libxlsxwriter-dev zlib1g-dev debhelper dpkg-dev fakeroot xvfb xauth gcovr lcov)
    ;;
  windows)
    packages+=(gcc-mingw-w64-x86-64-posix g++-mingw-w64-x86-64-posix mingw-w64-tools
      nasm perl xz-utils python3-pefile libgl1-mesa-dev libfontconfig1-dev
      libfreetype6-dev libx11-dev libx11-xcb-dev libxext-dev libxfixes-dev libxi-dev
      libxrender-dev libxcb1-dev libxcb-cursor-dev libxcb-glx0-dev libxcb-keysyms1-dev
      libxcb-image0-dev libxcb-shm0-dev libxcb-icccm4-dev libxcb-sync-dev
      libxcb-xfixes0-dev libxcb-shape0-dev libxcb-randr0-dev libxcb-render-util0-dev
      libxcb-util-dev libxcb-xkb-dev libxkbcommon-dev libxkbcommon-x11-dev)
    ;;
  *) printf 'Unknown setup mode: %s\n' "$mode" >&2; exit 2 ;;
esac
sudo apt-get update
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
if [[ $mode == windows ]]; then
  for compiler in gcc g++; do
    sudo update-alternatives --set "x86_64-w64-mingw32-$compiler" "/usr/bin/x86_64-w64-mingw32-$compiler-posix"
  done
fi
