# SPDX-License-Identifier: CC0-1.0
# Public-domain example code (CC0) - see ../LICENSE.
# =============================================================================
# generate-test-certs.cmake - lab-only self-signed certificates for the
# BACnet/SC listener (Network Port 2 / "Vermilion 2") in this example.
#
# Run as:  cmake -P scripts/generate-test-certs.cmake
#      or: cmake --build build --target test-certs
#
# WHY CMAKE SCRIPT MODE (not a .sh/.ps1 pair):
#   * CMake is already a hard prerequisite of this whole project on every
#     platform this example builds on (Windows/Linux/macOS) - one script, no
#     bash/PowerShell twins to keep in sync.
#   * No MSYS `/CN=` path-mangling footgun (a known plugfest-example gotcha
#     when a `-subj "/CN=..."` string is run through Git-for-Windows' bash,
#     which rewrites the leading "/" as a drive path).
#   * No `<(...)` process substitution (the SC manual's own Appendix B.3
#     recipe uses it and is bash-only) - this script writes each OpenSSL
#     extension file with plain `file(WRITE ...)` instead.
#
# WHAT THIS PRODUCES (all under certs/, gitignored - see .gitignore):
#   ca.key,  ca.crt   - a throwaway lab CA (ECDSA P-256, 10-year validity).
#   hub.key, hub.csr, hub.crt
#                     - this device's own operational certificate. EKU
#                       serverAuth+clientAuth (it is both a TLS server - the
#                       hub function's accept role - and, in a future phase,
#                       a TLS client - the hub connector role) with
#                       subjectAltName DNS:localhost, IP:127.0.0.1, and this
#                       machine's hostname, per the SC manual's Appendix B
#                       self-signed recipe.
#   node.key, node.crt
#                     - a client-only certificate (EKU clientAuth) for a test
#                       peer to authenticate with when connecting to the hub -
#                       see tests/sc/hub_listener_test.py.
#
# Every *.crt is verified against ca.crt with `openssl verify` before this
# script reports success. Existing files are never silently overwritten -
# pass -DFORCE=1 to regenerate everything from scratch.
#
# THIS IS LAB TESTING ONLY. A real deployment must use its own PKI (or a real
# CA), not this throwaway one - see README.md "BACnet/SC support" and
# TUTORIAL.md's productionising notes.
# =============================================================================

cmake_minimum_required(VERSION 3.15)

set(CERTS_DIR "${CMAKE_CURRENT_LIST_DIR}/../certs")
get_filename_component(CERTS_DIR "${CERTS_DIR}" ABSOLUTE)

# --- Find openssl -------------------------------------------------------------
# 1) whatever's on PATH, 2) the one vcpkg just built (built-from-source vcpkg
#    triplets ship an openssl.exe/openssl tool alongside the libraries),
# 3) Git-for-Windows' bundled openssl (present on every Windows dev machine
#    that has Git installed, even without a system OpenSSL install).
find_program(OPENSSL_EXECUTABLE
    NAMES openssl openssl.exe
    HINTS
        "${CMAKE_CURRENT_LIST_DIR}/../build/vcpkg_installed/x64-windows-static/tools/openssl"
        "${CMAKE_CURRENT_LIST_DIR}/../build/vcpkg_installed/x64-windows/tools/openssl"
        "$ENV{VCPKG_ROOT}/installed/x64-windows-static/tools/openssl"
        "$ENV{ProgramFiles}/Git/usr/bin"
        "$ENV{ProgramFiles}/Git/mingw64/bin"
        "C:/Program Files/Git/usr/bin"
)
if(NOT OPENSSL_EXECUTABLE)
    message(FATAL_ERROR
        "generate-test-certs.cmake: could not find an 'openssl' executable on "
        "PATH, in build/vcpkg_installed/*/tools/openssl, or in a Git-for-Windows "
        "install. Install OpenSSL (or Git for Windows, which bundles it) and "
        "re-run, or pass -D OPENSSL_EXECUTABLE=/path/to/openssl.")
endif()
message(STATUS "generate-test-certs.cmake: using openssl at ${OPENSSL_EXECUTABLE}")

file(MAKE_DIRECTORY "${CERTS_DIR}")

# --- Overwrite guard -----------------------------------------------------------
set(EXISTING_FILES "")
foreach(f ca.key ca.crt hub.key hub.csr hub.crt node.key node.crt)
    if(EXISTS "${CERTS_DIR}/${f}")
        list(APPEND EXISTING_FILES "${f}")
    endif()
endforeach()
if(EXISTING_FILES AND NOT FORCE)
    string(REPLACE ";" ", " EXISTING_FILES_STR "${EXISTING_FILES}")
    message(FATAL_ERROR
        "generate-test-certs.cmake: refusing to overwrite existing file(s) in "
        "${CERTS_DIR}: ${EXISTING_FILES_STR}. Pass -D FORCE=1 to regenerate "
        "everything from scratch (this invalidates any peer that trusted the "
        "old ca.crt).")
endif()

# --- Helper: run openssl, fail loudly on error --------------------------------
function(run_openssl)
    execute_process(
        COMMAND "${OPENSSL_EXECUTABLE}" ${ARGN}
        WORKING_DIRECTORY "${CERTS_DIR}"
        RESULT_VARIABLE _rc
        OUTPUT_VARIABLE _out
        ERROR_VARIABLE _err
    )
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR
            "generate-test-certs.cmake: 'openssl ${ARGN}' failed (exit ${_rc}).\n"
            "stdout: ${_out}\nstderr: ${_err}")
    endif()
endfunction()

# --- Hostname (for the hub cert's SAN) -----------------------------------------
cmake_host_system_information(RESULT LOCAL_HOSTNAME QUERY HOSTNAME)
if(NOT LOCAL_HOSTNAME)
    set(LOCAL_HOSTNAME "localhost")
endif()

message(STATUS "generate-test-certs.cmake: writing to ${CERTS_DIR}")

# --- 1. Lab CA (ECDSA P-256, self-signed, 10 years) ----------------------------
run_openssl(ecparam -name prime256v1 -genkey -noout -out ca.key)
run_openssl(req -new -x509 -key ca.key -out ca.crt -days 3650
    -subj "/C=CA/O=Chipkin Automation Systems (lab test)/CN=BACnet SC Example Test CA")

# --- 2. Hub operational certificate (serverAuth + clientAuth) ------------------
# EKU has BOTH: the hub accept role is a TLS SERVER; a future hub-connector
# role (Phase 3) making it a TLS CLIENT too - matches the SC manual's Appendix
# B recipe for a device that plays both TLS roles.
run_openssl(ecparam -name prime256v1 -genkey -noout -out hub.key)
run_openssl(req -new -key hub.key -out hub.csr -subj "/O=Chipkin Automation Systems (lab test)/CN=BACnetExampleBSCHUB-hub")

set(HUB_EXT_FILE "${CERTS_DIR}/hub.ext.cnf")
file(WRITE "${HUB_EXT_FILE}"
"basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:${LOCAL_HOSTNAME}
")
run_openssl(x509 -req -in hub.csr -CA ca.crt -CAkey ca.key -CAcreateserial
    -out hub.crt -days 825 -sha256 -extfile "${HUB_EXT_FILE}")
file(REMOVE "${HUB_EXT_FILE}")

# --- 3. Node test-peer certificate (clientAuth only) ---------------------------
# For a future test peer (tests/sc/hub_listener_test.py today; a real
# BACnetSCCli node later - see the plan's V3). Not used to serve anything, so
# no SAN is needed - SC identifies peers by certificate + VMAC/UUID in the
# protocol, not by hostname (see ScTransport.h's LCCSCF_SKIP_SERVER_CERT_
# HOSTNAME_CHECK note for the connector half, Phase 3).
run_openssl(ecparam -name prime256v1 -genkey -noout -out node.key)
run_openssl(req -new -key node.key -out node.csr -subj "/O=Chipkin Automation Systems (lab test)/CN=BACnetExampleBSCHUB-node")

set(NODE_EXT_FILE "${CERTS_DIR}/node.ext.cnf")
file(WRITE "${NODE_EXT_FILE}"
"basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
")
run_openssl(x509 -req -in node.csr -CA ca.crt -CAkey ca.key -CAcreateserial
    -out node.crt -days 825 -sha256 -extfile "${NODE_EXT_FILE}")
file(REMOVE "${NODE_EXT_FILE}")
file(REMOVE "${CERTS_DIR}/node.csr")

# --- 4. Verify everything against the CA ---------------------------------------
run_openssl(verify -CAfile ca.crt hub.crt)
run_openssl(verify -CAfile ca.crt node.crt)

message(STATUS "generate-test-certs.cmake: OK - ca.crt, hub.key/hub.csr/hub.crt, "
               "node.key/node.crt written and verified under ${CERTS_DIR}")
message(STATUS "LAB TESTING ONLY - do not use these certificates in production. "
               "See README.md \"BACnet/SC support\".")
