#!/usr/bin/env bash
# Builds fully static r2r-relay and r2r-probe binaries for other CPU
# architectures, using zig (clang + musl) as the cross compiler.
#
#   toolchain/build-cross.sh                 # x86_64 and aarch64
#   toolchain/build-cross.sh aarch64         # one target
#   toolchain/build-cross.sh x86_64 aarch64 armv7l riscv64
#
# Targets are named after `uname -m` on the machine that will run the binary,
# so install.sh can pick the right file without a lookup table. Results land in
# dist/r2r-relay-<arch> and dist/r2r-probe-<arch>, with dist/SHA256SUMS.
#
# Why zig: it carries its own C/C++ standard library and musl for every target
# it supports, so the whole toolchain is one apt package and the binaries carry
# no glibc requirement at all (the gcc build published until now needed glibc
# 2.38+). musl resolves hostnames from resolv.conf without NSS plugins, so a
# static binary loses nothing there either. Only OpenSSL has to be built per
# target; that happens once and is cached under toolchain/sysroot.
#
# Memory: the relay instantiates Beast twice and one translation unit peaks
# well over 1 GB; JOBS defaults to 1 for the 2-4 GB machines relays run on.
#
#   JOBS=2            parallel compile jobs for the relay (default 1)
#   OPENSSL_JOBS=2    parallel jobs for OpenSSL (default: CPU count)
#   SMOKE=1           run scripts/smoke-test.sh on each result (needs qemu-user
#                     binfmt for foreign targets)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TC="$ROOT/toolchain"
ZIG="${ZIG:-zig}"
OPENSSL_VER="${OPENSSL_VER:-3.5.8}"
JOBS="${JOBS:-1}"
OPENSSL_JOBS="${OPENSSL_JOBS:-$(nproc)}"

declare -A TRIPLE=( [x86_64]=x86_64-linux-musl [aarch64]=aarch64-linux-musl
                    [armv7l]=arm-linux-musleabihf [riscv64]=riscv64-linux-musl )
declare -A OSSL=(   [x86_64]=linux-x86_64 [aarch64]=linux-aarch64
                    [armv7l]=linux-armv4 [riscv64]=linux64-riscv64 )
# Baseline CPUs: what every board people actually run is guaranteed to have.
declare -A MCPU=(   [x86_64]=x86_64 [aarch64]=generic [armv7l]=generic+v7a+vfp3+neon [riscv64]=baseline_rv64 )

targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(x86_64 aarch64)
for a in "${targets[@]}"; do
    [ -n "${TRIPLE[$a]:-}" ] || { echo "unknown target '$a' (x86_64 aarch64 armv7l riscv64)" >&2; exit 1; }
done

command -v "$ZIG" >/dev/null || { echo "zig not found: apt install zig" >&2; exit 1; }
command -v perl  >/dev/null || { echo "perl is needed to configure OpenSSL" >&2; exit 1; }
echo "zig $($ZIG version), openssl $OPENSSL_VER, targets: ${targets[*]}"

# ---------------------------------------------------------------------------
# Compiler wrappers. CMake and OpenSSL both want a plain compiler path, so each
# target gets a two-line script that adds -target and -mcpu.
# ---------------------------------------------------------------------------
mkdir -p "$TC/bin"
wrap() { # wrap <name> <zig subcommand> [extra flags...]
    local name="$1" sub="$2"; shift 2
    printf '#!/bin/sh\nexec "%s" %s %s "$@"\n' "$ZIG" "$sub" "$*" > "$TC/bin/$name"
    chmod +x "$TC/bin/$name"
}
wrap zig-ar ar
wrap zig-ranlib ranlib
for a in "${targets[@]}"; do
    t="${TRIPLE[$a]}"
    wrap "$t-cc"  cc  -target "$t" -mcpu="${MCPU[$a]}"
    wrap "$t-c++" c++ -target "$t" -mcpu="${MCPU[$a]}"
done

# Boost and nlohmann_json are header-only and architecture-independent, so the
# host's copies serve every target. They are exposed through one directory that
# contains nothing else, so no glibc header can leak into a musl build.
mkdir -p "$TC/sysroot/common/include"
for h in boost nlohmann; do
    [ -e "$TC/sysroot/common/include/$h" ] || ln -s "/usr/include/$h" "$TC/sysroot/common/include/$h"
    [ -d "/usr/include/$h" ] || { echo "/usr/include/$h missing: apt install libboost-dev nlohmann-json3-dev" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# OpenSSL, once per target, into toolchain/sysroot/<triple>.
# ---------------------------------------------------------------------------
build_openssl() { # build_openssl <arch>
    local a="$1" t="${TRIPLE[$1]}" sysroot="$TC/sysroot/${TRIPLE[$1]}" tarball work
    [ -f "$sysroot/lib/libssl.a" ] && { echo "[$a] openssl already built"; return 0; }
    tarball="$TC/src/openssl-$OPENSSL_VER.tar.gz"
    if [ ! -f "$tarball" ]; then
        mkdir -p "$TC/src"
        echo "[$a] fetching openssl-$OPENSSL_VER"
        curl -fsSL -o "$tarball" "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VER/openssl-$OPENSSL_VER.tar.gz"
        curl -fsSL -o "$tarball.sha256" "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VER/openssl-$OPENSSL_VER.tar.gz.sha256"
    fi
    (cd "$TC/src" && echo "$(awk '{print $1}' "$tarball.sha256")  $(basename "$tarball")" | sha256sum -c --quiet)
    work="$TC/work/openssl-$t"
    rm -rf "$work"; mkdir -p "$work"
    tar xzf "$tarball" -C "$work" --strip-components=1
    echo "[$a] configuring openssl for ${OSSL[$a]}"
    (cd "$work" && ./Configure "${OSSL[$a]}" --prefix="$sysroot" --libdir=lib \
        no-shared no-dso no-module no-tests no-apps no-docs no-legacy no-engine \
        no-comp no-zlib no-ssl3 no-weak-ssl-ciphers no-uplink \
        CC="$TC/bin/$t-cc" AR="$TC/bin/zig-ar" RANLIB="$TC/bin/zig-ranlib" \
        > "$work/configure.log" 2>&1) || { tail -30 "$work/configure.log"; exit 1; }
    echo "[$a] building openssl (-j$OPENSSL_JOBS)"
    (cd "$work" && make -j"$OPENSSL_JOBS" build_libs > "$work/build.log" 2>&1) || { tail -40 "$work/build.log"; exit 1; }
    (cd "$work" && make install_dev > "$work/install.log" 2>&1) || { tail -20 "$work/install.log"; exit 1; }
    rm -rf "$work"
    echo "[$a] openssl installed in $sysroot"
}

build_relay() { # build_relay <arch>
    local a="$1" t="${TRIPLE[$1]}" sysroot="$TC/sysroot/${TRIPLE[$1]}" bdir="$ROOT/build-cross/$1"
    mkdir -p "$bdir"
    echo "[$a] configuring relay"
    cmake -S "$ROOT" -B "$bdir" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE="$TC/zig-musl.cmake" \
        -DR2R_ZIG_TARGET="$t" -DR2R_TARGET_PROCESSOR="$a" -DR2R_SYSROOT="$sysroot" \
        -DR2R_HEADER_ONLY_INCLUDE_DIR="$TC/sysroot/common/include" \
        -DR2R_FULLY_STATIC=ON > "$bdir.configure.log" 2>&1 || { tail -40 "$bdir.configure.log"; exit 1; }
    grep -E 'OPENSSL_(SSL|CRYPTO)_LIBRARY:' "$bdir/CMakeCache.txt" | grep -q "$sysroot" \
        || { echo "[$a] CMake did not pick the cross-built OpenSSL; see $bdir/CMakeCache.txt" >&2; exit 1; }
    echo "[$a] building relay (-j$JOBS; this takes a while)"
    cmake --build "$bdir" -j"$JOBS" > "$bdir.build.log" 2>&1 || { tail -60 "$bdir.build.log"; exit 1; }
    mkdir -p "$ROOT/dist"
    cp "$bdir/r2r-relay" "$ROOT/dist/r2r-relay-$a"
    cp "$bdir/r2r-probe" "$ROOT/dist/r2r-probe-$a"
    echo "[$a] dist/r2r-relay-$a ($(du -h "$ROOT/dist/r2r-relay-$a" | cut -f1)), dist/r2r-probe-$a"
}

for a in "${targets[@]}"; do
    build_openssl "$a"
    build_relay "$a"
    if [ "${SMOKE:-0}" = "1" ]; then
        echo "[$a] smoke test"
        "$ROOT/scripts/smoke-test.sh" "$ROOT/build-cross/$a" 2>&1 | tail -4
    fi
done
(cd "$ROOT/dist" && sha256sum r2r-relay-* r2r-probe-* > SHA256SUMS && cat SHA256SUMS)
