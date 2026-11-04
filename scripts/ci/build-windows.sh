#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
work=${WINDOWS_BUILD_DIRECTORY:-$repo/.build/windows}
prefix=${WINDOWS_TOOLCHAIN_DIRECTORY:-$repo/.build/toolchain}
jobs=${BUILD_JOBS:-$(nproc)}
mingw=x86_64-w64-mingw32
deps=$prefix/deps
host=$prefix/host
target=$prefix/target
cflags='-O2 -fstack-protector-strong -fstack-clash-protection -fcf-protection -fno-strict-overflow -fno-delete-null-pointer-checks -fno-plt -Wformat -Wformat-security -Werror=format-security'
ldflags='-Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va -Wl,--no-insert-timestamp -Wl,--disable-auto-image-base -Wl,-O1'
mkdir -p "$work" "$prefix"
qt_version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["qt"]["version"])' "$repo/scripts/ci/sources.json")
# Also checked inside the script so local builds cannot reuse an incompatible cache.
identity=$( { cat /etc/os-release; "$mingw-g++" -dumpfullversion; cat "$repo/scripts/ci/sources.json" "$0"; } | sha256sum | cut -d' ' -f1)
if [[ ! -f $prefix/identity || $(cat "$prefix/identity") != "$identity" ]]; then
  # These are dedicated toolchain output directories, never a system prefix.
  rm -rf -- "$deps" "$host" "$target" "$work/sources" "$work/host-build" "$work/target-build"
  mkdir -p "$deps" "$work/sources"
  python3 "$repo/scripts/ci/fetch-sources.py" "$work/downloads"
  for component in openssl libzip libxlsxwriter zlib-ng; do
    mkdir -p "$work/sources/$component"
    tar -xf "$work/downloads/$component.tar.gz" -C "$work/sources/$component" --strip-components=1
  done
  mkdir -p "$work/sources/qt"
  tar -xf "$work/downloads/qt.tar.xz" -C "$work/sources/qt" --strip-components=1
  patch --directory="$work/sources/qt" -p1 < "$work/downloads/qtbase-fix.diff"
  cat > "$work/mingw.cmake" <<EOF
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER $mingw-gcc)
set(CMAKE_CXX_COMPILER $mingw-g++)
set(CMAKE_RC_COMPILER $mingw-windres)
set(CMAKE_FIND_ROOT_PATH "$deps" "${MINGW_SYSROOT:-/usr/$mingw}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_C_FLAGS_INIT "$cflags")
set(CMAKE_CXX_FLAGS_INIT "$cflags")
set(CMAKE_EXE_LINKER_FLAGS_INIT "$ldflags")
EOF
  cmake_args=(-G Ninja "-DCMAKE_TOOLCHAIN_FILE=$work/mingw.cmake" -DCMAKE_BUILD_TYPE=Release
    "-DCMAKE_INSTALL_PREFIX=$deps" -DBUILD_SHARED_LIBS=OFF)
  cmake -S "$work/sources/zlib-ng" -B "$work/sources/zlib-ng/build" "${cmake_args[@]}" \
    -DZLIB_COMPAT=ON -DZLIB_ENABLE_TESTS=OFF -DWITH_GTEST=OFF
  cmake --build "$work/sources/zlib-ng/build" --parallel "$jobs"
  cmake --install "$work/sources/zlib-ng/build"
  (
    cd "$work/sources/openssl"
    # Deliberately split the reviewed compiler flag list into individual arguments.
    ./Configure mingw64 no-shared no-tests no-docs no-apps --cross-compile-prefix="$mingw-" \
      --prefix="$deps" --openssldir="$deps/ssl" --libdir=lib $cflags
    make -j"$jobs"
    make install_sw
  )
  library_args=("-DZLIB_ROOT=$deps" "-DZLIB_LIBRARY=$deps/lib/libz.a" "-DZLIB_INCLUDE_DIR=$deps/include"
    "-DOPENSSL_ROOT_DIR=$deps" -DOPENSSL_USE_STATIC_LIBS=ON)
  cmake -S "$work/sources/libzip" -B "$work/sources/libzip/build" "${cmake_args[@]}" "${library_args[@]}" \
    -DBUILD_TOOLS=OFF -DBUILD_REGRESS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_DOC=OFF \
    "-DCMAKE_C_FLAGS=$cflags -DDWORD_MAX=0xffffffffUL" \
    '-DCMAKE_C_STANDARD_LIBRARIES=-lws2_32 -lcrypt32 -lbcrypt'
  cmake --build "$work/sources/libzip/build" --parallel "$jobs"
  cmake --install "$work/sources/libzip/build"
  cmake -S "$work/sources/libxlsxwriter" -B "$work/sources/libxlsxwriter/build" "${cmake_args[@]}" "${library_args[@]}" \
    -DBUILD_TESTS=OFF -DBUILD_EXAMPLES=OFF -DUSE_OPENSSL_MD5=ON
  cmake --build "$work/sources/libxlsxwriter/build" --parallel "$jobs"
  cmake --install "$work/sources/libxlsxwriter/build"
  mkdir -p "$work/host-build" "$work/target-build"
  (
    cd "$work/host-build"
    "$work/sources/qt/configure" -prefix "$host" -release -opensource -confirm-license \
      -nomake examples -nomake tests -no-icu -no-opengl -no-feature-sql-odbc \
      -no-feature-sql-psql -no-feature-sql-mysql -sql-sqlite
    cmake --build . --parallel "$jobs"
    cmake --install .
  )
  # Installed host tools are sufficient; discard their large precompiled headers
  # before building the target to keep the cold build within runner disk space.
  rm -rf -- "$work/host-build"
  (
    cd "$work/target-build"
    "$work/sources/qt/configure" -prefix "$target" -release -opensource -confirm-license \
      -static -static-runtime -no-shared -platform linux-g++-64 -xplatform win32-g++ \
      -device-option CROSS_COMPILE="$mingw-" -qt-host-path "$host" \
      -nomake examples -nomake tests -no-icu -no-opengl -openssl-linked -sql-sqlite \
      -no-feature-sql-odbc -no-feature-sql-psql -no-feature-sql-mysql -optimize-size -- \
      "-DCMAKE_TOOLCHAIN_FILE=$work/mingw.cmake" "${library_args[@]}" \
      "-DCMAKE_C_FLAGS_RELEASE=$cflags" "-DCMAKE_CXX_FLAGS_RELEASE=$cflags" \
      "-DCMAKE_EXE_LINKER_FLAGS_RELEASE=$ldflags"
    cmake --build . --parallel "$jobs"
    cmake --install .
  )
  printf '%s\n' "$identity" > "$prefix/identity"
fi
[[ $("$host/bin/qmake" -query QT_VERSION) == "$qt_version" ]]
[[ $("$target/bin/qmake" -query QT_VERSION) == "$qt_version" ]]
mkdir -p "$work/app" "$repo/.build/dist"
cd "$work/app"
# Qt's cross-qmake shell wrapper expands $* without quoting. Invoke the host
# tool with the target configuration so compiler assignments stay intact.
"$host/bin/qmake" -qtconf "$target/bin/target_qt.conf" "$repo/STIGQter.pro" "STIGQTER_STATIC_DEPS=$deps" \
  "QMAKE_CFLAGS_RELEASE+=$cflags" "QMAKE_CXXFLAGS_RELEASE+=$cflags" "QMAKE_LFLAGS_RELEASE+=$ldflags"
make -j"$jobs"
"$mingw-strip" --strip-all --preserve-dates release/STIGQter.exe
python3 "$repo/scripts/ci/verify-windows.py" release/STIGQter.exe
version=$(cat "$repo/VERSION")
package=$work/package
mkdir -p "$package"
cp release/STIGQter.exe "$package/STIGQter.exe"
cp "$repo/CHANGES.md" "$repo/LICENSE" "$repo/README.md" "$repo/scripts/ci/sources.json" "$package/"
cd "$package"
zip -9 "$repo/.build/dist/STIGQter-$version-win64.zip" STIGQter.exe CHANGES.md LICENSE README.md sources.json
cp STIGQter.exe "$repo/.build/dist/STIGQter-$version-win64.exe"
cd "$repo/.build/dist"
sha256sum ./*-win64.zip ./*-win64.exe > SHA256SUMS-windows.txt
