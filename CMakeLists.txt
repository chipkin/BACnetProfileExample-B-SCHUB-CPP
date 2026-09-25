# =============================================================================
# CMake build for the BACnet B-SCHUB (BACnet/SC Hub) C++ example.
#
# This example links the CAS BACnet Stack through the CASBACnetStack::Adapter CMake
# target (submodules/cas-bacnet-stack/adapters/cpp) and calls the stack's C API
# (BACnetStack_*, via CASBACnetStackAdapter.h) directly. It builds and ships in the
# adapter's default SOURCE mode: the stack's source/*.cpp are compiled straight into
# the executable, so there is no library or DLL to build, ship, or install first and
# the build is the same two commands on every platform. (The adapter also offers
# STATIC and DLL modes - see its CMakeLists.txt - but they need a prebuilt library
# and this example does not use them.)
#
# Build:
#   cmake -B build -S .
#   cmake --build build --config Release --parallel
# Run (from the example folder):
#   ./build/BACnetExampleBSCHUB          (Linux/macOS)
#   .\build\Release\BACnetExampleBSCHUB.exe   (Windows)
# =============================================================================

cmake_minimum_required(VERSION 3.15)

# --- vcpkg toolchain auto-detection ------------------------------------------
# Must happen BEFORE project() - the toolchain file is what makes
# find_package(libwebsockets)/find_package(OpenSSL) below resolve at all.
# If the caller already passed -D CMAKE_TOOLCHAIN_FILE=..., respect it as-is
# (this keeps CI, which sets the toolchain explicitly, working unchanged).
# Otherwise, if VCPKG_ROOT is set in the environment (Visual Studio bundles
# one; so does a manual vcpkg install), point at its toolchain file so the
# documented two-command build (cmake -B build -S . / cmake --build build)
# keeps working with no extra flags.
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

# On Windows, default to the static triplet so libwebsockets/OpenSSL match
# the CAS BACnet Stack adapter's own static-runtime default below - a mixed
# triplet here is the #1 way to hit an LNK2038 _ITERATOR_DEBUG_LEVEL / MD-vs-MT
# mismatch at link time. Only takes effect on a fresh vcpkg-toolchain configure;
# an explicit -D VCPKG_TARGET_TRIPLET=... on the command line still wins.
if(WIN32 AND NOT DEFINED VCPKG_TARGET_TRIPLET)
    set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "Vcpkg target triplet")
endif()

project(BACnetProfileExample_CPP_B_SCHUB CXX C)


# Default to a Release build.
#
# Without this, a single-config generator (Unix Makefiles / Ninja - the default
# on Linux and macOS) leaves CMAKE_BUILD_TYPE EMPTY, and the documented
# `cmake --build build --config Release` is SILENTLY IGNORED there: --config
# only means anything to a multi-config generator like Visual Studio. The result
# is that the whole stack (~600 files) compiles at -O0 and the customer never
# finds out. Windows is unaffected, which is exactly why this survived so long.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Locate the pieces this project ships -----------------------------------
# The shared helper is vendored into this repository at ./common.
if(NOT DEFINED EXAMPLES_COMMON_DIR)
    set(EXAMPLES_COMMON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/common")
endif()

# The CAS BACnet Stack is a git submodule of this repository, at
# ./submodules/cas-bacnet-stack. Run `git submodule update --init --recursive`
# after cloning. (Override with -D CAS_STACK_DIR=... to use a stack elsewhere.)
if(NOT DEFINED CAS_STACK_DIR)
    set(CAS_STACK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/submodules/cas-bacnet-stack")
endif()

if(NOT EXISTS "${CAS_STACK_DIR}/adapters/cpp/CMakeLists.txt")
    message(FATAL_ERROR
        "CAS BACnet Stack adapter not found under: ${CAS_STACK_DIR}\n"
        "The stack is a git submodule. After cloning this repository, run:\n"
        "    git submodule update --init --recursive\n"
        "Or pass -D CAS_STACK_DIR=/path/to/cas-bacnet-stack to use a stack elsewhere.")
endif()

# --- MSVC runtime library (must match across the whole link) ----------------
# vcpkg's x64-windows-static triplet builds libwebsockets/OpenSSL against the
# static CRT (/MT, /MTd for Debug). Set CMAKE_MSVC_RUNTIME_LIBRARY the same way
# BEFORE add_subdirectory(adapter) below, so the CAS BACnet Stack adapter's own
# SOURCE-mode compile of ~600 stack files picks up the identical setting -
# otherwise the link fails with LNK2038 _ITERATOR_DEBUG_LEVEL / MD-vs-MT
# mismatches between the stack, this example, and the vcpkg libraries.
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# --- BACnet/SC transport dependencies (vcpkg) --------------------------------
# libwebsockets + OpenSSL back the WebSocket+TLS transport in sc_transport/.
# Resolved via the vcpkg toolchain set up above (VCPKG_ROOT / CMAKE_TOOLCHAIN_FILE).
find_package(libwebsockets CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# --- The CAS BACnet Stack, via its CMake adapter target ---------------------
# CAS_BACNET_STACK_LINK is the adapter's own cache variable (SOURCE/STATIC/DLL,
# default SOURCE) - set it BEFORE add_subdirectory() so the adapter target picks it up.
# See submodules/cas-bacnet-stack/adapters/cpp/CMakeLists.txt for what each mode does.
add_subdirectory("${CAS_STACK_DIR}/adapters/cpp" cas-bacnet-stack-adapter)

# --- The shared example helper ----------------------------------------------
set(COMMON_SOURCES
    "${EXAMPLES_COMMON_DIR}/CASExampleHelper.cpp"
    "${EXAMPLES_COMMON_DIR}/CASExampleLog.cpp"
    "${EXAMPLES_COMMON_DIR}/SimpleUDP.cpp")

# --- The executable ---------------------------------------------------------
# sc_transport/ is the real BACnet/SC WebSocket+TLS transport (libwebsockets +
# OpenSSL) and its stack<->transport glue - see docs/bacnet-sc-transport-plan.md
# and sc_transport/README.md. Phase 1's scratch sc_transport_spike.{h,cpp} (which
# only settled the lws Service() non-blocking mechanism) is gone now that this
# lands - see CHANGELOG.md.
set(SC_TRANSPORT_SOURCES
    "sc_transport/ScTransport.cpp"
    "sc_transport/ScTransportRouter.cpp"
    "sc_transport/HttpServer.cpp")

add_executable(BACnetExampleBSCHUB
    main.cpp
    config.cpp
    cert_tool.cpp
    cert_store.cpp
    ${SC_TRANSPORT_SOURCES}
    ${COMMON_SOURCES})

target_include_directories(BACnetExampleBSCHUB PRIVATE
    "${EXAMPLES_COMMON_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries(BACnetExampleBSCHUB PRIVATE
    CASBACnetStack::Adapter
    websockets
    OpenSSL::SSL
    OpenSSL::Crypto)

# --- Warnings on OUR sources only -------------------------------------------
# Apply strict warnings to the example + helper sources, but NOT to the bundled
# third-party stack (~600 files, built inside the CASBACnetStack::Adapter target)
# which would be noisy and isn't ours to fix.
if(MSVC)
    set(EXAMPLE_WARNINGS "/W4")
else()
    set(EXAMPLE_WARNINGS "-Wall;-Wextra")
endif()
set_source_files_properties(main.cpp config.cpp cert_tool.cpp cert_store.cpp ${SC_TRANSPORT_SOURCES} ${COMMON_SOURCES}
    PROPERTIES COMPILE_OPTIONS "${EXAMPLE_WARNINGS}")

# --- Platform sockets --------------------------------------------------------
# ws2_32  = Winsock (UDP); iphlpapi = GetAdaptersInfo (local broadcast address);
# dbghelp/winmm = required by libuv (pulled in transitively by libwebsockets'
# static libuv event-loop backend, even though sc_transport doesn't use it) -
# same fix as ../plugfest-example/CMakeLists.txt for the identical LNK2019s
# (SymSetOptions/SymGetOptions/MiniDumpWriteDump from libuv's process.c).
if(WIN32)
    # advapi32 = GetNamedSecurityInfoA/GetAce/ConvertSidToStringSidA (config.cpp's
    # best-effort config-file-permissions check, Task 1's secrets-handling pass).
    target_link_libraries(BACnetExampleBSCHUB PRIVATE ws2_32 iphlpapi dbghelp winmm advapi32)
endif()

# --- Lab test certificates ---------------------------------------------------
# `cmake --build build --target test-certs` (or `cmake -P scripts/generate-test-certs.cmake`
# directly) regenerates certs/ - see that script for what it produces and why.
# Not a dependency of BACnetExampleBSCHUB: the app itself checks for missing
# cert files at run time and logs the generate command (ScTransport::StartListening).
add_custom_target(test-certs
    COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate-test-certs.cmake"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Generating BACnet/SC lab test certificates under certs/")
