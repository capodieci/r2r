cmake_minimum_required(VERSION 3.16)

# CMake 4 removed the FindBoost module; Boost >= 1.70 ships its own config.
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()

project(r2r_relay VERSION 1.0.2 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# -O2 rather than -O3. listener.cpp instantiates the whole Beast stack twice
# (plain and TLS) and needs well over 2 GB to compile at -O3, which OOM-kills
# the compiler on the 2-4 GB VPS these relays run on. The relay is I/O-bound;
# the difference in throughput is not measurable.
if(NOT MSVC)
  set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG" CACHE STRING "Release flags" FORCE)
endif()

option(R2R_STATIC_CXX  "Statically link libstdc++/libgcc"          ON)
# Links OpenSSL statically as well, so the result is one file with no runtime
# dependency beyond libc: copy it to a relay and run it.
option(R2R_STATIC_SSL  "Statically link OpenSSL into the binary"   OFF)
# Links libc in as well, so the binary carries no glibc version requirement and
# runs on distributions far older than the one that built it. Peers are dialled
# by IP, which a statically linked resolver handles; hostnames would need NSS
# plugins that a static binary cannot load, so --advertise and gossip entries
# must be addresses, not names.
option(R2R_FULLY_STATIC "Link libc statically too (implies R2R_STATIC_SSL)" OFF)
option(R2R_BUILD_PROBE "Build the r2r-probe diagnostic client"     ON)
# r2r-vectors prints docs/protocol-vectors.json: known-answer vectors for
# re-implementations of the relay. A developer tool; never installed.
option(R2R_BUILD_VECTORS "Build the r2r-vectors test-vector generator" OFF)
option(R2R_ASAN        "Build with Address/UB sanitizers"          OFF)
option(R2R_WERROR      "Treat warnings as errors"                  OFF)
# Build profiles (see CMakePresets.json for the three canonical combinations):
#   full      DOORWAY=ON  ADMIN_UI=ON   -- public doorway site + admin console
#   adminOnly DOORWAY=OFF ADMIN_UI=ON   -- admin console, no public pages
#   headless  DOORWAY=OFF ADMIN_UI=OFF  -- storage + routing + CLI admin only
option(R2R_WITH_DOORWAY  "Serve the doorway web site"              ON)
option(R2R_WITH_ADMIN_UI "Serve the admin web console"             ON)

if(R2R_FULLY_STATIC)
  set(R2R_STATIC_SSL ON)
endif()

find_package(Threads REQUIRED)
if(R2R_STATIC_SSL)
  set(OPENSSL_USE_STATIC_LIBS ON)
endif()
find_package(OpenSSL 1.1.1 REQUIRED)

# Boost.Beast + Boost.Asio are header-only; no compiled Boost libraries are needed.
# A cross build (toolchain/build-cross.sh) hands both header-only libraries
# over as one directory instead of letting find_package walk the host, so no
# host system header can end up on a musl include path.
set(R2R_HEADER_ONLY_INCLUDE_DIR "" CACHE PATH
    "Directory holding boost/ and nlohmann/ for a cross build; empty = find_package")
if(R2R_HEADER_ONLY_INCLUDE_DIR)
  foreach(_h boost/beast.hpp nlohmann/json.hpp)
    if(NOT EXISTS "${R2R_HEADER_ONLY_INCLUDE_DIR}/${_h}")
      message(FATAL_ERROR "R2R_HEADER_ONLY_INCLUDE_DIR lacks ${_h}")
    endif()
  endforeach()
  add_library(Boost::headers INTERFACE IMPORTED)
  target_include_directories(Boost::headers SYSTEM INTERFACE "${R2R_HEADER_ONLY_INCLUDE_DIR}")
  add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
  target_include_directories(nlohmann_json::nlohmann_json SYSTEM INTERFACE "${R2R_HEADER_ONLY_INCLUDE_DIR}")
else()
  find_package(Boost 1.74 REQUIRED)

  find_package(nlohmann_json 3.9 QUIET)
  if(NOT nlohmann_json_FOUND)
    message(STATUS "nlohmann_json not found locally; fetching it")
    include(FetchContent)
    FetchContent_Declare(nlohmann_json
      URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
    FetchContent_MakeAvailable(nlohmann_json)
  endif()
endif()

# ---------------------------------------------------------------------------
# SQLite3 -- vendored amalgamation, always statically linked into the relay.
# ---------------------------------------------------------------------------
add_library(r2r_sqlite3 STATIC third_party/sqlite3/sqlite3.c)
target_include_directories(r2r_sqlite3 PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite3>)
target_compile_definitions(r2r_sqlite3 PUBLIC
  SQLITE_THREADSAFE=1              # serialized: safe from any thread
  SQLITE_DQS=0                     # no double-quoted string literals
  SQLITE_DEFAULT_MEMSTATUS=0
  SQLITE_DEFAULT_FOREIGN_KEYS=1
  SQLITE_DEFAULT_WAL_SYNCHRONOUS=1
  SQLITE_LIKE_DOESNT_MATCH_BLOBS
  SQLITE_MAX_EXPR_DEPTH=0
  SQLITE_OMIT_DEPRECATED
  SQLITE_OMIT_SHARED_CACHE
  SQLITE_OMIT_LOAD_EXTENSION=1     # no runtime extension loading
  SQLITE_OMIT_AUTOINIT
  SQLITE_USE_URI=1
  SQLITE_ENABLE_API_ARMOR)
target_link_libraries(r2r_sqlite3 PUBLIC Threads::Threads m)
if(NOT MSVC)
  target_compile_options(r2r_sqlite3 PRIVATE -w)
endif()

# ---------------------------------------------------------------------------
# Relay core (shared by the daemon and the probe tool)
# ---------------------------------------------------------------------------
add_library(r2r_core STATIC
  src/util.cpp
  src/log.cpp
  src/config.cpp
  src/crypto.cpp
  src/db.cpp
  src/blobstore.cpp
  src/peers.cpp
  src/protocol.cpp
  src/onion.cpp
  src/doorway.cpp
  src/admin_ui.cpp
  src/http_routes.cpp
  src/hub.cpp
  src/peer_manager.cpp
  src/listener.cpp
  src/session_plain.cpp
  src/session_tls.cpp)

target_include_directories(r2r_core PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)

target_link_libraries(r2r_core PUBLIC
  r2r_sqlite3
  nlohmann_json::nlohmann_json
  Threads::Threads)

if(R2R_STATIC_SSL AND OPENSSL_ROOT_DIR)
  # An OpenSSL built for this purpose (toolchain/build-cross.sh: no-comp,
  # no-zlib, no-dso) depends on nothing but libc, so the archives link as is.
  target_include_directories(r2r_core SYSTEM PUBLIC ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(r2r_core PUBLIC
    ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ${CMAKE_DL_LIBS})
elseif(R2R_STATIC_SSL)
  # The imported OpenSSL targets carry -lzstd and -l:libjitterentropy.a in
  # their interface, and -lzstd resolves to the shared object no matter what
  # else is on the line. Linking the archives by absolute path instead is the
  # only reliable way to end up with nothing but libc behind us.
  set(_r2r_saved_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
  set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
  find_library(R2R_ZSTD_A zstd)
  find_library(R2R_JITTER_A jitterentropy)
  find_library(R2R_ZLIB_A z)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${_r2r_saved_suffixes})

  foreach(_lib R2R_ZSTD_A R2R_JITTER_A R2R_ZLIB_A)
    if(NOT ${_lib})
      message(FATAL_ERROR
        "R2R_STATIC_SSL needs static archives that are not installed. On Debian/Ubuntu:\n"
        "  apt install libzstd-dev libjitterentropy3-dev zlib1g-dev libssl-dev")
    endif()
  endforeach()

  target_include_directories(r2r_core SYSTEM PUBLIC ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(r2r_core PUBLIC
    ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY}
    ${R2R_ZSTD_A} ${R2R_JITTER_A} ${R2R_ZLIB_A} ${CMAKE_DL_LIBS})
else()
  target_link_libraries(r2r_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

if(TARGET Boost::headers)
  target_link_libraries(r2r_core PUBLIC Boost::headers)
else()
  target_include_directories(r2r_core SYSTEM PUBLIC ${Boost_INCLUDE_DIRS})
endif()

target_compile_definitions(r2r_core PUBLIC
  R2R_VERSION="${PROJECT_VERSION}"
  BOOST_ASIO_HAS_STD_INVOKE_RESULT=1)
if(R2R_WITH_DOORWAY)
  target_compile_definitions(r2r_core PUBLIC R2R_WITH_DOORWAY=1)
endif()
if(R2R_WITH_ADMIN_UI)
  target_compile_definitions(r2r_core PUBLIC R2R_WITH_ADMIN_UI=1)
endif()

if(NOT MSVC)
  target_compile_options(r2r_core PRIVATE -Wall -Wextra -Wpedantic -Wno-unused-parameter)
  if(R2R_WERROR)
    target_compile_options(r2r_core PRIVATE -Werror)
  endif()
endif()

if(R2R_ASAN)
  target_compile_options(r2r_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer -g)
  target_link_options(r2r_core PUBLIC -fsanitize=address,undefined)
endif()

# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------
add_executable(r2r-relay src/main.cpp)
target_link_libraries(r2r-relay PRIVATE r2r_core)

if(R2R_FULLY_STATIC)
  target_link_options(r2r-relay PRIVATE -static)
elseif(R2R_STATIC_CXX AND NOT R2R_ASAN AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_link_options(r2r-relay PRIVATE -static-libstdc++ -static-libgcc)
endif()

if(R2R_BUILD_PROBE)
  add_executable(r2r-probe tools/probe.cpp)
  target_link_libraries(r2r-probe PRIVATE r2r_core)
  if(R2R_FULLY_STATIC)
    target_link_options(r2r-probe PRIVATE -static)
  elseif(R2R_STATIC_CXX AND NOT R2R_ASAN AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(r2r-probe PRIVATE -static-libstdc++ -static-libgcc)
  endif()
endif()

if(R2R_BUILD_VECTORS)
  add_executable(r2r-vectors tools/protocol-vectors.cpp)
  target_link_libraries(r2r-vectors PRIVATE r2r_core)
  if(R2R_FULLY_STATIC)
    target_link_options(r2r-vectors PRIVATE -static)
  elseif(R2R_STATIC_CXX AND NOT R2R_ASAN AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(r2r-vectors PRIVATE -static-libstdc++ -static-libgcc)
  endif()
endif()

include(GNUInstallDirs)
install(TARGETS r2r-relay RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(R2R_BUILD_PROBE)
  install(TARGETS r2r-probe RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(FILES systemd/r2r-relay.service DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system OPTIONAL)
