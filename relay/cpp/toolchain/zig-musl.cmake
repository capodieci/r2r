# CMake toolchain file: zig as a C/C++ cross compiler for static musl targets.
# Driven by toolchain/build-cross.sh, which passes:
#   R2R_ZIG_TARGET              e.g. aarch64-linux-musl
#   R2R_TARGET_PROCESSOR        e.g. aarch64 (what `uname -m` prints there)
#   R2R_SYSROOT                 where the cross-built OpenSSL was installed
#   R2R_HEADER_ONLY_INCLUDE_DIR a directory holding only boost/ and nlohmann/
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ${R2R_TARGET_PROCESSOR})

set(_r2r_tc_bin ${CMAKE_CURRENT_LIST_DIR}/bin)
set(CMAKE_C_COMPILER   ${_r2r_tc_bin}/${R2R_ZIG_TARGET}-cc)
set(CMAKE_CXX_COMPILER ${_r2r_tc_bin}/${R2R_ZIG_TARGET}-c++)
set(CMAKE_AR     ${_r2r_tc_bin}/zig-ar     CACHE FILEPATH "archiver")
set(CMAKE_RANLIB ${_r2r_tc_bin}/zig-ranlib CACHE FILEPATH "ranlib")

# Everything the binary links comes from the per-target sysroot, never from
# the host. Headers likewise: the only host headers allowed in are the
# architecture-independent header-only libraries, through their own directory.
set(CMAKE_FIND_ROOT_PATH ${R2R_SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(OPENSSL_ROOT_DIR ${R2R_SYSROOT} CACHE PATH "cross-built OpenSSL")
set(OPENSSL_USE_STATIC_LIBS ON)

# musl sizes new threads' stacks from PT_GNU_STACK (128 KiB otherwise); match
# glibc's 8 MiB so nothing that was fine on the gcc build gets a smaller stack.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static -s -Wl,-z,stack-size=8388608")
