# =============================================================================
# CMake build for the BACnet B-SCHUB (BACnet/SC Hub) C++ example.
#
# This example links the CAS BACnet Stack through the CASBACnetStack::Adapter CMake
# target (submodules/cas-bacnet-stack/adapters/cpp) and calls the stack's C API
# (BACnetStack_*, via CASBACnetStackAdapter.h) directly. This example builds and
# ships in STATIC mode: CAS_BACNET_STACK_LINK=STATIC links a prebuilt
# CASBACnetStack_x64_Release.lib / libCASBACnetStack_x64_Release.a, built first by
# tools/build-stack-static.sh from the stack's own project files. (The adapter also
# offers a SOURCE mode that compiles the stack's source/ straight into the
# executable with no separate library build; this example is not built that way.)
#
# Build:
#   tools/build-stack-static.sh BACnetProfileExample-B-SCHUB-CPP   (from the series root)
#   cmake -B build -S . -DCAS_BACNET_STACK_LINK=STATIC
#   cmake --build build --config Release --parallel
# Run (from the example folder):
#   ./build/BACnetExampleBSCHUB          (Linux/macOS)
#   .\build\Release\BACnetExampleBSCHUB.exe   (Windows)
# =============================================================================

cmake_minimum_required(VERSION 3.15)
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

# --- The CAS BACnet Stack, via its CMake adapter target ---------------------
# CAS_BACNET_STACK_LINK is the adapter's own cache variable (SOURCE/STATIC/DLL,
# default SOURCE) - set it BEFORE add_subdirectory() so the adapter target picks it up.
# See submodules/cas-bacnet-stack/adapters/cpp/CMakeLists.txt for what each mode does.
add_subdirectory("${CAS_STACK_DIR}/adapters/cpp" cas-bacnet-stack-adapter)

# --- The shared example helper ----------------------------------------------
set(COMMON_SOURCES
    "${EXAMPLES_COMMON_DIR}/CASExampleHelper.cpp"
    "${EXAMPLES_COMMON_DIR}/SimpleUDP.cpp")

# --- The executable ---------------------------------------------------------
add_executable(BACnetExampleBSCHUB
    main.cpp
    ${COMMON_SOURCES})

target_include_directories(BACnetExampleBSCHUB PRIVATE
    "${EXAMPLES_COMMON_DIR}")

target_link_libraries(BACnetExampleBSCHUB PRIVATE CASBACnetStack::Adapter)

# --- Warnings on OUR sources only -------------------------------------------
# Apply strict warnings to the example + helper sources, but NOT to the bundled
# third-party stack (~600 files, built inside the CASBACnetStack::Adapter target)
# which would be noisy and isn't ours to fix.
if(MSVC)
    set(EXAMPLE_WARNINGS "/W4")
else()
    set(EXAMPLE_WARNINGS "-Wall;-Wextra")
endif()
set_source_files_properties(main.cpp ${COMMON_SOURCES}
    PROPERTIES COMPILE_OPTIONS "${EXAMPLE_WARNINGS}")

# --- Platform sockets -------------------------------------------------------
# ws2_32  = Winsock (UDP); iphlpapi = GetAdaptersInfo (local broadcast address).
if(WIN32)
    target_link_libraries(BACnetExampleBSCHUB PRIVATE ws2_32 iphlpapi)
endif()
