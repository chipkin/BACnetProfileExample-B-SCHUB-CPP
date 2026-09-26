// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE. The CAS BACnet Stack itself is
// a separate, commercially licensed product and is not covered by CC0.
// =============================================================================
// BACnet Profile Example - B-SCHUB (BACnet/SC Hub) - C++
//
// This example implements the BACnet "B-SCHUB" (BACnet Secure Connect Hub)
// device profile with the CAS BACnet Stack:
//
//     DS-RP-B   - respond to ReadProperty requests,
//     DS-RPM-B  - respond to ReadPropertyMultiple requests,
//     DM-DDB-B  - respond to Who-Is/I-Am (device discovery),
//     DM-DOB-B  - respond to Who-Has/I-Have (object discovery),
//     DM-DCC-B  - respond to DeviceCommunicationControl,
//     NM-SCH-B  - operate a BACnet/SC hub function: accept SC node connections
//                 and relay traffic between them.
//
// It keeps the base series objects - three read-only sensor inputs, each with a
// colour name (the convention shared across this example series). The two
// Network Ports and four File objects below deliberately break from that
// convention: they are purpose-named instead, because a BACnet/SC hub's
// operator-facing tooling (and this file's own comments) benefit far more
// from "which port is the SC one" and "which File is the CSR" being
// self-evident than from another colour:
//
//     Device 389022                "Chipkin Example B-SCHUB"                   (instance configurable with --deviceID)
//     Analog Input  1               "Bronze"                    (REAL, degrees Celsius; read-only)
//     Network Port 1                "BACnet IP"                 (the BACnet/IP port - required, kept
//                                                                 active so the device stays
//                                                                 discoverable over plain BACnet/IP)
//     Network Port 2                "BACnet SC"                 (the BACnet/SC port - hub function)
//     File 1                        "Operational Certificate"   (the hub's operational certificate,
//                                                                 operational-certificate.pem; writable)
//     File 2                        "Certificate Signing Request" (the hub's CSR,
//                                                                 certificate-signing-request.pem; read-only)
//     File 3                        "Issuer Certificate Slot 1" (issuer-certificate.pem; writable)
//     File 4                        "Issuer Certificate Slot 2" (issuer-certificate-2.pem, or slot 1's
//                                                                 certificate until one is written; writable)
//
// Every object has a Description saying what it is for (ObjectDescription()).
//
// This profile does NOT require WriteProperty, COV, alarms, scheduling or
// trending, so this example leaves those off (unlike B-ASC, its seed, it does
// not add DS-WP-B or any commandable output - NM-SCH-B replaces that delta).
//
// -----------------------------------------------------------------------------
// BACNET/SC TRANSPORT (NM-SCH-B) - see docs/bacnet-sc-transport-plan.md and
// sc_transport/README.md for the full design; this section is the summary.
//
// Read from submodules/cas-bacnet-stack/docs/CAS BACnet Stack - BACnet SC
// Manual_v6.md and the doc comments on every BACnetStack_*SC* / *Websocket*
// export in CASBACnetStackDLL.h (search "BACnetSC Functions"): the stack owns
// the BACnet/SC PROTOCOL - the Hello handshake, the hub/node/direct-connect
// state machines, BVLC framing, certificate-object bookkeeping, the SC Network
// Port properties. It does NOT own the transport. Verbatim, from the doc
// comment on BACnetStack_RegisterCallbackInitiateWebsocket:
//
//     "The stack implements no WebSocket or TLS itself."
//
// The stack asks the HOST to open/close/listen-on raw WebSocket(+TLS)
// connections via four callbacks (RegisterCallbackInitiateWebsocket,
// RegisterCallbackDisconnectWebsocket, RegisterCallbackSCStartListening,
// RegisterCallbackSCStopListening) and expects status reported back through
// BACnetStack_SetBACnetSCWebSocketStatus. This example supplies that transport
// for real, both roles: sc_transport/ScTransport (libwebsockets + OpenSSL, via
// vcpkg - mutual TLS 1.3, subprotocol "hub.bsc.bacnet.org", binary WebSocket
// framing, the 1497-byte ingress ceiling enforced) and
// sc_transport/ScTransportRouter (the stack<->transport glue, dispatching
// ReceiveMessageForPort/SendMessageForPort by Network Port instance) - see
// those headers for the design, sc_transport/README.md for the wire-level
// contract, and docs/bacnet-sc-transport-plan.md for how it was built and
// verified across all four implementation phases.
//
// BOTH roles are real and have each been verified against a real peer, not
// just against this repository's own test scripts:
//
//   * LISTENER (hub-function accept role): CallbackSCStartListening/
//     CallbackSCStopListening forward to ScTransport::StartListening()/
//     StopListening(). A real BACnet/SC node (BACnetSCCli.exe, Role=node)
//     connected, mutually authenticated over TLS 1.3, and completed
//     Who-Is/I-Am/ReadProperty discovery of this device over BACnet/SC.
//   * CONNECTOR (hub/node initiate role): CallbackInitiateWebsocket/
//     CallbackDisconnectWebsocket forward to ScTransport::Connect()/
//     Disconnect(). OFF by default (this hub-only example does not need one
//     to answer a node's own requests - see docs/bacnet-sc-transport-plan.md
//     open risk #8) and turns on when --sc-hub-uri is given on the command
//     line (see main() below). Verified against both a hand-built fake hub
//     (tests/sc/fake_hub_server.py) and a real hub (BACnetSCCli.exe,
//     Role=hub), reaching hub-connector state ConnectedPrimary.
//
// The BACnet/IP Network Port (1, "BACnet IP") stays active and fully functional
// throughout, so the example remains discoverable and testable over plain
// BACnet/IP regardless of BACnet/SC - including while SC peers are connected
// (main()'s loop alternates IP-first/SC-first each Tick so neither starves the
// other - see ScTransportRouter.h).
//
// Network Port 2's SC certificate properties (Operational_Certificate_File,
// Certificate_Signing_Request_File, Issuer_Certificate_Files) point at 4
// read-only File objects (see the object list above), served from
// --sc-cert-dir by RegisterCallbackReadFile (section 2d below) - never the
// private key (certs/hub.key has no File object at all). Verified over
// BACnet/IP with AtomicReadFile: byte-for-byte against certs/hub.crt, and the
// private key confirmed unreachable through any File object instance.
// Certificate validation is entirely this example's job: the stack has no TLS
// path of its own and no certificate-validation callback (the two it once
// declared were never called and were removed - stack IFC-039). The CA-chain
// check in sc_transport/ScTransport's TLS contexts is the device's certificate
// policy.
//
// This device's certificate policy is CA-chain validation, performed by the
// TLS library (OpenSSL, via libwebsockets) at handshake time, plus revocation
// checking when a CRL is installed (issue #15): no UUID-in-SAN binding, and the connector skips hostname checking
// (LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK - SC certificates identify BACnet/SC
// devices, not DNS hosts, so there is no hostname to check against; the CA
// chain is still verified). See TUTORIAL.md for what productionizing this
// further - a real CA, certificate rotation, hostname/identity policy - looks
// like.
// -----------------------------------------------------------------------------

#include "CASExampleHelper.h"
#include "CASExampleLog.h"
#include "CASBACnetStackExampleConstants.h"
#include "CASBACnetStackAdapter.h" // the CAS BACnet Stack C API (BACnetStack_*); call
                                    // LoadBACnetFunctions() before any BACnetStack_* call -
                                    // see the top of main() below.
#include "sc_transport/ScTransport.h"
#include "sc_transport/ScTransportRouter.h"
#include "sc_transport/HttpServer.h" // GET /health, /metrics + POST /certs/<slot> (this batch's Tasks 3/4)
#include "config.h" // --config <path> support (Task 2) - see config.h
#include "cert_tool.h" // --generate-certs / --add-client-certs - see cert_tool.h
#include "cert_store.h" // certificate File object contents + clause 19.8.3 staging - see cert_store.h
#include "log_file.h"   // --log-file: console output also to a rotating file - see log_file.h
#include "service.h"    // Windows service / SIGTERM handling - see service.h

// Unlike sc_transport/ScTransport.h (which forward-declares lws types
// specifically to avoid this), main.cpp already needs the real
// libwebsockets.h here for LwsLogCallback/lws_set_log_level below (Item 5 -
// see that section's own comment) - main.cpp has no equivalent header/
// implementation split to protect.
#include <libwebsockets.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <chrono>
#include <string>
#include <sys/stat.h> // stat()/_stat() - File objects' File_Size + Modification_Date (section 2d)
#include <time.h>     // gmtime() - File objects' Modification_Date

#if defined(_WIN32)
#include <windows.h> // Sleep()
#else
#include <unistd.h>  // usleep()
#endif

using namespace CASBACnetStackExampleConstants;

// -----------------------------------------------------------------------------
// 1. Example + device configuration
// -----------------------------------------------------------------------------
static const char* APP_NAME = "BACnet B-SCHUB (BACnet/SC Hub) Example - C++";
static const char* APP_VERSION = "1.3.0";

// The device instance. BACnet requires this to be configurable, so it defaults
// to 389022 and can be overridden on the command line with --deviceID.
static uint32_t g_deviceInstance = 389022;

// ---- Device identity: CHANGE ALL OF THIS BEFORE YOU SHIP --------------------
// Everything in this block is read by clients and shown to the operator in every
// discovery tool on the network. Left as-is, your product will appear on a real
// site announcing itself as a Chipkin demo. None of it is cosmetic:
// Object_Name must be unique across the BACnet internetwork, and Model_Name /
// Vendor_Identifier are what a building operator uses to identify your device.
// -----------------------------------------------------------------------------

// Your BACnet Vendor Identifier. 389 = Chipkin Automation Systems; change this
// to YOUR company's vendor ID before shipping a product. Vendor IDs are assigned
// by ASHRAE - request one (free) at https://bacnet.org/assigned-vendor-ids/.
// Update VENDOR_NAME below to match.
static const uint32_t VENDOR_IDENTIFIER = 389;

// The Device object's Object_Name.
//
// THIS IS THE ONE THAT WILL BITE YOU. Object_Name must be unique across the
// whole BACnet internetwork. The device instance is configurable with
// --deviceID, so it is easy to ship two units, configure their instances
// correctly, and still have BOTH announce the same Object_Name - a spec
// violation, and a hard BTL failure. So the name is configurable too:
// --device-name / config-file device-name (issue #33). DEVICE_NAME_DEFAULT is
// only what an unconfigured unit calls itself.
static const char* DEVICE_NAME_DEFAULT = "Chipkin Example B-SCHUB";
static std::string g_deviceName = DEVICE_NAME_DEFAULT;

// Each Network Port's Network_Number (1..65534) - --ip-network-number /
// --sc-network-number or the config file's ip-network-number /
// sc-network-number (issue #33). 0 = not configured: the port reports 0 with
// Network_Number_Quality "unknown". When set, it is reported with quality
// "configured". This device isn't a router, so the number is informational -
// it records which BACnet network each port is on.
static uint16_t g_ipNetworkNumber = 0;
static uint16_t g_scNetworkNumber = 0;

// Where this example lives - shown in the Device's Description and on the
// HTTP status page. Change both to your own product's pages.
static const char* PROJECT_URL = "https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP";
static const char* STACK_PRODUCT_URL = "https://store.chipkin.com/services/stacks/bacnet-stack";

// Device identity strings (read by clients, and used to populate I-Am).
//   VENDOR_NAME - your company name; it must match VENDOR_IDENTIFIER above.
//   MODEL_NAME  - your model designation. This is what a building operator reads
//                 to identify your device in a discovery tool.
static const char* VENDOR_NAME = "Chipkin Automation Systems";
static const char* MODEL_NAME = "CAS BACnet Stack Example - B-SCHUB";

// DeviceCommunicationControl password. A management station may include a password
// with a DeviceCommunicationControl (or ReinitializeDevice) request; the device
// accepts the command only if it matches. Empty ("") accepts any request (no
// password required). Change the DEFAULT below to your device's secret before
// shipping - note it still crosses the wire in plaintext, so this is a guard
// against accidents, not a security boundary.
//
// SET ONLY VIA THE --config FILE'S "dcc-password" KEY (2026-09 secrets-handling
// pass, Task 1) - there is deliberately NO "--dcc-password <string>" CLI flag
// (common/CASExampleHelper::ParseDccPasswordArg still EXISTS in common/ 2.6.0+
// for any other example that wants a CLI flag; this repo simply stopped
// calling it for that purpose - see docs/manual.md "Configuration file" for why a
// CLI argument is a real exposure a config-file key is not: it is visible in
// process listings/shell history on every platform). Not a compile-time
// constant, so it is NOT `static const` like the rest of this identity block;
// see main()'s config-file-loading block, which points this at
// fileConfig.dccPassword's storage (a local that lives for the rest of
// main()) when the key is present. POST /certs/<slot> has its own secret,
// http-upload-token (g_httpUploadToken) - see issue #23.
static const char* g_dccPassword = "";  // default: "" = no password required

// POST /certs/<slot>'s bearer token (config file "http-upload-token" only, for
// the same process-listing reason as dcc-password). Empty = upload disabled.
static std::string g_httpUploadToken;

// Application_Software_Version (12) is just APP_VERSION - one source of
// truth, so it can never drift from what --version/the startup banner
// prints (it did drift: this used to be a separate hardcoded "1.0.0"
// constant nobody updated across 12 patch releases - found via a real
// device read, not code review, by someone actually testing the built
// device's Device object properties).
//
// Firmware_Revision (44) is meant to name the underlying platform/stack,
// not this example's own version - built at runtime from the CAS BACnet
// Stack's own BACnetStack_GetAPIMajorVersion()/etc. (the same 4 calls
// common/CASExampleHelper.cpp's PrintVersion() already uses for the
// startup banner's "CAS BACnet Stack version: X.Y.Z.W" line), so it can
// never go stale either - see g_firmwareRevision below, populated once
// right after LoadBACnetFunctions() succeeds (those functions are what
// the version getters themselves are, so they must be loaded first).
static std::string g_firmwareRevision;

// The sensor objects (all instance 1) and their colour names - the series'
// base object set (unchanged from every other example).
static const uint32_t ANALOG_INPUT_INSTANCE = 1;       // "Bronze"

// Network Port 1 - the BACnet/IP port every BACnet device must have. Kept
// active so this example stays discoverable over plain BACnet/IP regardless of
// the BACnet/SC transport outcome (see the file header note above).
static const uint32_t NETWORK_PORT_INSTANCE = 1;       // "BACnet IP"

// --bacnet-ip on|off / config-file bacnet-ip (issue #35). On by default. Off
// makes this a BACnet/SC-only device, for sites that want no unencrypted
// BACnet traffic: no UDP socket is opened, Network Port 1 is not created (so
// it is not in Object_List), and every service - Who-Is/I-Am included - is
// reachable only over BACnet/SC. If BACnet/SC then isn't listening (missing
// certificates, say), the device is unreachable over BACnet: main() warns.
static bool g_bacnetIpEnabled = true;
static const uint32_t MAX_APDU_LENGTH = 1476;          // BACnet/IP APDU length

// Network Port 2 - the BACnet/SC port, hosting the hub function (NM-SCH-B).
// BACnetNetworkType::secureConnect = 11 (source/BACnetNetworkType.h). This is a
// LOCAL constant, not added to common/CASBACnetStackExampleConstants.h - that
// file is the series-wide vendored common/ helper (owned by B-SS-CPP; changing
// it is a separate, serialised protocol - see the series runbook §1). A single
// example needing one extra constant does not justify a common/ change.
static const uint8_t NETWORK_PORT_NETWORK_TYPE_SECURE_CONNECT = 11;
static const uint32_t SC_NETWORK_PORT_INSTANCE = 2;     // "BACnet SC"

// The hub function's max simultaneous inbound peer connections.
//
// SC_MAX_HUB_CONNECTIONS_LIMIT is a HARD limit for this example: it is for
// evaluation and testing, not production, so it accepts at most 4 BACnet/SC
// devices at a time. Asking for more (--sc-max-hub-connections or the config
// file's sc-max-hub-connections) is refused at start-up with an error pointing
// at Chipkin sales - see CheckScMaxHubConnectionsLimit(). A value from 1 to the
// limit is allowed; the default is the limit.
//
// Enforced by the STACK: BACnetSCHubFunctionManager rejects a Connect-Request
// once the accepted-connection table holds maxConnections peers - a BACnet/SC
// protocol-level rejection (the WebSocket/TLS handshake in
// sc_transport/ScTransport completes first; the stack rejects at the BVLC-SC
// Connect-Request that follows).
static const uint16_t SC_MAX_HUB_CONNECTIONS_LIMIT = 4;
static const uint16_t SC_MAX_HUB_CONNECTIONS_DEFAULT = SC_MAX_HUB_CONNECTIONS_LIMIT;
static const char* const SUPPORT_EMAIL = "support@chipkin.com";

// The runtime value actually passed to BACnetStack_SetBACnetSCHubFunctionConfig -
// see main()'s CLI-parsing block (--sc-max-hub-connections / config-file
// sc-max-hub-connections; CLI > config file > SC_MAX_HUB_CONNECTIONS_DEFAULT).
static uint16_t g_scMaxHubConnections = SC_MAX_HUB_CONNECTIONS_DEFAULT;

// How fast the hub-function listener accepts NEW inbound connection ATTEMPTS,
// enforced by sc_transport/ScTransport before the TLS handshake starts (see
// ScTransport::SetConnectionRateLimits). Distinct from
// SC_MAX_HUB_CONNECTIONS_DEFAULT above, which bounds CONCURRENT connections.
//   SC_RATE_LIMIT_DEFAULT       - attempts/second from any ONE source address
//                                 (--sc-rate-limit), so one flooding host
//                                 can't starve devices on other addresses.
//   SC_RATE_LIMIT_TOTAL_DEFAULT - attempts/second for the whole listener
//                                 (--sc-rate-limit-total), a ceiling on a
//                                 flood from many addresses.
// Both are generous: a device's own reconnect back-off is seconds, not
// milliseconds, so they only bite under a real flood. 0 turns a limit off.
static const uint16_t SC_RATE_LIMIT_DEFAULT = 10;
static const uint16_t SC_RATE_LIMIT_TOTAL_DEFAULT = 50;

// The runtime values (CLI > config file > the defaults above) - see main().
static uint16_t g_scRateLimit = SC_RATE_LIMIT_DEFAULT;
static uint16_t g_scRateLimitTotal = SC_RATE_LIMIT_TOTAL_DEFAULT;

// BACnet/SC interoperability relaxation (issue #19), OFF by default. When on,
// main() calls BACnetStack_SetBACnetSCCompatibilityFlags with
// SC_COMPATIBILITY_ACCEPT_CONNECT_ACCEPT_WITHOUT_HELLO, the stack's one defined
// compatibility flag: the hub CONNECTOR (--sc-hub-uri) then accepts a
// Connect-Accept that omits the Hello destination option, which 135-2024 AB.2.2
// makes mandatory - some older hubs leave it out. It is a deliberate deviation
// from the standard, so leave it off unless such a hub needs it.
// It does NOT relax the hub FUNCTION: a device that connects to this hub with a
// Connect-Request without Hello is still refused - the stack has no switch for
// that (see docs/manual.md "BACnet/SC compatibility").
static const uint8_t SC_COMPATIBILITY_ACCEPT_CONNECT_ACCEPT_WITHOUT_HELLO = 0x01;
static bool g_scAcceptHubWithoutHello = false;

// The 4 read-only File objects Network Port 2's SC certificate properties point at - see
// BACnetStack_SetBACnetSCCertificateFileObjects's call in main() and RegisterCallbackReadFile
// in section 2d. Same "local constant, not common/" rationale as
// NETWORK_PORT_NETWORK_TYPE_SECURE_CONNECT above: File is a series-wide object type, but no
// other example in the series has needed one yet, so there is nothing to share in common/.
// Named for what each one is (Operational Certificate / Certificate Signing Request / Issuer Certificate Slot 1-2)
// rather than a colour, deliberately breaking from this series' usual naming convention - see
// the file header note above for why.
static const uint32_t FILE_OPERATIONAL_CERT_INSTANCE = 1;  // "Operational Certificate"   - certs/hub.crt
static const uint32_t FILE_CSR_INSTANCE = 2;                // "Certificate Signing Request" - certs/hub.csr
static const uint32_t FILE_ISSUER_CERT_1_INSTANCE = 3;      // "Issuer Certificate Slot 1" - certs/ca.crt
static const uint32_t FILE_ISSUER_CERT_2_INSTANCE = 4;      // "Issuer Certificate Slot 2" - certs/ca.crt (same file;
                                                              // BACnetStack_SetBACnetSCCertificateFileObjects
                                                              // requires exactly 2 issuer slots
                                                              // regardless - this lab setup has one
                                                              // CA, so both point at it, per plan)
// File_Access_Method (135-2024 Table 12-16): 0 = Record Access, 1 = Stream Access
// (BACnetStack_AddFileObject's own doc comment). All 4 File objects above are stream access -
// there is no record structure to a PEM file.
static const uint8_t FILE_ACCESS_METHOD_STREAM = 1;

// BACnetObjectType::file (submodules/cas-bacnet-stack/source/BACnetObjectType.h) and the File
// object's own required-property identifiers (BACnetPropertyIdentifier.h) - none of these are in
// common/CASBACnetStackExampleConstants.h (no other example in the series has a File object yet),
// so, same as OBJECT_TYPE_FILE's sibling local constants above, they are defined locally here.
static const uint16_t OBJECT_TYPE_FILE = 10;
static const uint32_t PROPERTY_IDENTIFIER_ARCHIVE = 13;
static const uint32_t PROPERTY_IDENTIFIER_FILE_SIZE = 42;
static const uint32_t PROPERTY_IDENTIFIER_FILE_TYPE = 43;
static const uint32_t PROPERTY_IDENTIFIER_MODIFICATION_DATE = 71;
static const uint32_t PROPERTY_IDENTIFIER_READ_ONLY = 99;

// AtomicReadFile (BACnetServicesSupported.h: atomicReadFile = 6) - its own
// confirmed service, NOT implied by adding a File object (BACnetStack_AddFileObject's
// own doc comment says nothing about enabling it, and in practice a client's
// AtomicReadFile against an unserviced device times out rather than erroring -
// found by testing V6, not documented). Same "local constant" rationale as the
// other File-object constants above.
static const uint32_t SERVICE_ATOMIC_READ_FILE = 6;

// The device-B side of the BACnet/SC certificate procedures (ANSI/ASHRAE
// 135-2024 clause 19.8.3, e.g. the CAS BACnet Explorer's certificate page):
// a client writes File_Size = 0 (WriteProperty, common/'s
// SERVICE_WRITE_PROPERTY) and AtomicWriteFile's a new certificate into a
// certificate File object, then sends ReinitializeDevice ACTIVATE_CHANGES
// (SERVICE_REINITIALIZE_DEVICE). See cert_store.h for how the writes are staged.
static const uint32_t SERVICE_ATOMIC_WRITE_FILE = 7;     // BACnetServicesSupported.h atomicWriteFile
// BACnetReinitializedStateOfDevice activateChanges (WARMSTART comes from common/).
static const uint32_t REINITIALIZE_STATE_ACTIVATE_CHANGES = 7;
static const uint32_t ERROR_CODE_INVALID_CONFIGURATION_DATA = 46;

// Set by the ReinitializeDevice callback once new certificates are committed;
// the main loop then reloads the TLS contexts (see ScTransport::ReloadCredentials).
static bool g_scReloadCredentialsRequested = false;

// The certificate revocation list file (issue #15) - optional, see
// ScTlsFiles::crlPath. The main loop checks it every few seconds and reloads
// TLS when it appears, changes or disappears, so installing a new CRL takes
// effect without a restart.
static std::string g_scCrlPath;

// A cheap fingerprint of the CRL file: its size and modification time, or ""
// when it doesn't exist.
static std::string FileFingerprint(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return std::string();
    }
    return std::to_string((long long)st.st_size) + "@" + std::to_string((long long)st.st_mtime);
}

// The file TLS trusts peers against: every issuer certificate from both
// Issuer_Certificate_Files slots (CertStore::WriteTrustedIssuerBundle), so a
// newly added issuer is trusted alongside the existing one.
static std::string g_scTrustedIssuersPath;

// The BACnet/SC hub accept role's WebSocket/TLS listener - CLI-configurable
// (--sc-port, --sc-cert-dir; see ParseSCPortArg/ParseSCCertDirArg below), since
// unlike the stub this replaces, ScTransport actually opens this port.
static uint16_t g_scPort = 47819;
static std::string g_scCertDir = "./certs";
// Built from g_scPort once the CLI has been parsed - see main(). "0.0.0.0"
// binds every interface (ScTransport::StartListening treats that host - or an
// empty one - as "bind all", the same as a NULL lws iface).
static std::string g_scHubAcceptUri;

// The BACnet/SC hub CONNECTOR (initiator) role - CLI-configurable
// (--sc-hub-uri, --sc-failover-uri; see ParseScUriArg below). OFF unless
// --sc-hub-uri is given: BACnetStack_SetBACnetSCHubConnectorForNetworkPort
// rejects an empty primary URI, and this hub-only example does not need one
// to answer a node's own requests (plan open risk #8) - it exists so this
// example can ALSO demonstrate NM-SCH-B's connector side, e.g. dialing out to
// another hub (a real one, or a second instance of this same example).
static std::string g_scHubUri;      // primary hub URI to dial; empty = connector role off
static std::string g_scFailoverUri; // optional failover hub URI; empty = none configured

// The read-only health/metrics HTTP endpoint (Task 3) and the certificate
// upload endpoint (Task 4) - both served by g_httpServer below.
// --http-port / config-file http-port; distinct from --port (BACnet/IP,
// default 47808) and --sc-port (BACnet/SC, default 47819).
static uint16_t g_httpPort = 8080;
// --http-bind / config-file http-bind. Defaults to loopback-only; see
// HttpServer.h's Start() doc comment for why binding this anywhere else is
// an explicit opt-in this example warns loudly about, every run, rather than
// a setting with no consequence.
static std::string g_httpBindAddress = "127.0.0.1";
// --http-tls / config-file http-tls: serve the HTTP endpoints over HTTPS
// (issue #22) with g_httpTlsCert/g_httpTlsKey - by default the hub's own
// operational certificate and private key from --sc-cert-dir. Off by default,
// like the loopback-only bind: on 127.0.0.1 nothing travels over a network.
static bool g_httpTls = false;
static std::string g_httpTlsCert;  // --http-tls-cert; "" = the operational certificate
static std::string g_httpTlsKey;   // --http-tls-key; "" = the hub's private key
static CASSc::HttpServer g_httpServer;

// Process start time (steady clock - immune to wall-clock adjustments),
// captured at the top of main() - source of the "uptime" field in the
// health/metrics snapshot (Task 2's 'm' keypress and Task 3's GET
// /health//metrics).
static std::chrono::steady_clock::time_point g_startTime;

// The real WebSocket/TLS transport (sc_transport/ScTransport.h) and the glue
// that dispatches the stack's ReceiveMessageForPort/SendMessageForPort
// callbacks between it and Network Port 1's UDP socket (sc_transport/
// ScTransportRouter.h). Both are globals (not locals in main()) because the
// four BACnet/SC transport callbacks below - plain C function pointers the
// stack calls with no user-data argument - need to reach g_scTransport.
static CASSc::ScTransport g_scTransport;
// Declared after g_scTransport (intra-TU global init order follows
// declaration order, and this takes a reference to it - see
// ScTransportRouter.h's constructor).
static CASSc::ScTransportRouter g_scRouter(NETWORK_PORT_INSTANCE, SC_NETWORK_PORT_INSTANCE, g_scTransport);

// BACnet/SC device UUID (135-2024 AB.1.5.3) - REQUIRED, set exactly once. A
// real device should generate/persist a stable random UUID (RFC 4122 v4) per
// unit; this example uses a fixed, clearly-a-demo value so every run of the
// example is reproducible. CHANGE THIS before using the pattern on real
// hardware - two devices sharing a UUID is a protocol violation.
static const uint8_t SC_DEVICE_UUID[16] = {
    0x53, 0x43, 0x48, 0x55, 0x42, 0x2d, 0x44, 0x45,   // "SCHUB-DE"
    0x4d, 0x4f, 0x2d, 0x33, 0x38, 0x39, 0x30, 0x32    // "MO-38902" (-> ...389022)
};

// BACnet/IP addressing the Network Port reports. The IP address and subnet mask
// are filled in at start-up from the host's primary interface; the gateway is
// left unset (0.0.0.0) for this example. The stack also uses IP_Address +
// BACnet_IP_UDP_Port to build the port's MAC_Address automatically.
static uint8_t g_ipAddress[4] = { 0, 0, 0, 0 };
static uint8_t g_ipSubnetMask[4] = { 0, 0, 0, 0 };
static uint8_t g_ipDefaultGateway[4] = { 0, 0, 0, 0 };
static uint16_t g_bacnetIpUdpPort = 47808;

// Analog Input 1's live present value (degrees Celsius). Starts at 21.5 and is
// nudged by the up/down arrow keys. A real sensor would update this from
// hardware instead.
static float g_analogInput1Value = 21.5f;

// -----------------------------------------------------------------------------
// 2. Property "get" callbacks
//
// The stack calls these when a client reads a property. For each data type the
// stack uses a separate callback. We return true (and fill *value) when we
// recognise the (object, property) pair, and false otherwise.
//
// THE errorCode OUT-PARAMETER. Every Get callback ends with uint32_t* errorCode.
// The stack PRESETS it to success (84) before the call, and reads it only if you
// return false. That gives a declining callback two distinct meanings:
//
//   1. return false and LEAVE errorCode ALONE  -> "I have no opinion on this
//      property." The stack falls back to its own handling (see below).
//   2. return false and SET *errorCode         -> "This read fails, with THIS
//      BACnet error." The client gets exactly that Error-PDU.
//
// WHAT false-WITHOUT-AN-ERROR-CODE ACTUALLY DOES - the most important paragraph
// in this file, and the opposite of what most people assume. It does NOT
// reliably produce a BACnet error. The stack errors only for the handful of
// properties it refuses to invent: Present_Value, Number_Of_States,
// Relinquish_Default, Local_Date, Local_Time, and a Network Port's APDU_Length
// (declining one of those now reads back as Error: read-access-denied, where
// older stack versions said value-not-initialized).
// For EVERYTHING ELSE, a false return means the stack SILENTLY SUBSTITUTES a
// default:
//     Object_Name -> the literal string "undefined"
//     Units       -> no-units (95)
//     otherwise   -> a datatype zero-value
//
// AND THAT FALLBACK IS LORE-BEARING, WHICH IS WHY WE DO NOT "FIX" IT HERE.
// It is tempting to end every callback with *errorCode = unknown-property so
// nothing is ever silently invented. That breaks the device. The stack relies on
// the decline-and-fabricate path to answer required properties the application
// is not expected to serve - the Device's Max_APDU_Length_Accepted, APDU_Timeout
// and Number_Of_APDU_Retries among them. Name an error on the catch-all return
// and those required properties start failing instead of answering.
// So: set *errorCode ONLY where THIS device knows the read is wrong. There is
// exactly one such case below (State_Text with an out-of-range array index); the
// catch-all `return false` at the end of each callback deliberately leaves
// errorCode alone.
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// 2a-i. File object helpers (phase 4) - map a File object instance to the file
// it serves under --sc-cert-dir, and read that file's size/bytes/mtime off
// disk. Shared by GetPropertyCharString/UnsignedInteger/Bool/Date/Time and
// RegisterCallbackReadFile below (section 2d). NEVER lists hub.key here - the
// private key has no File object and is never reachable through any of these.
// -----------------------------------------------------------------------------

// True if fileInstance is one of the 4 certificate/CSR File objects above.
static bool IsScCertFileInstance(const uint32_t fileInstance) {
    return fileInstance == FILE_OPERATIONAL_CERT_INSTANCE || fileInstance == FILE_CSR_INSTANCE ||
           fileInstance == FILE_ISSUER_CERT_1_INSTANCE || fileInstance == FILE_ISSUER_CERT_2_INSTANCE;
}

// Returns the filename (relative to g_scCertDir) for one of the 4 File object
// instances above, or "" if fileInstance isn't one of them. The names follow
// the Network Port properties each file backs (see cert_tool.h), e.g.
// operational-certificate.pem for Operational_Certificate_File. A directory
// made by an earlier release still uses the older names
// (hub.crt, hub.csr, ca.crt); CertTool::ResolveCertFile picks whichever exists.
static std::string ScCertFileRelativePath(const uint32_t fileInstance) {
    switch (fileInstance) {
        case FILE_OPERATIONAL_CERT_INSTANCE:
            return CertTool::ResolveCertFile(g_scCertDir, CertTool::OPERATIONAL_CERTIFICATE_FILE,
                                             CertTool::LEGACY_OPERATIONAL_CERTIFICATE_FILE);
        case FILE_CSR_INSTANCE:
            return CertTool::ResolveCertFile(g_scCertDir, CertTool::CERTIFICATE_SIGNING_REQUEST_FILE,
                                             CertTool::LEGACY_CERTIFICATE_SIGNING_REQUEST_FILE);
        case FILE_ISSUER_CERT_1_INSTANCE:
            return CertTool::ResolveCertFile(g_scCertDir, CertTool::ISSUER_CERTIFICATE_FILE,
                                             CertTool::LEGACY_ISSUER_CERTIFICATE_FILE);
        case FILE_ISSUER_CERT_2_INSTANCE:
            // Slot 2 has its own file, so a client can add a second issuer
            // without overwriting slot 1. Until something is written to it,
            // it serves slot 1's certificate (CertStore's read fallback).
            return CertTool::ISSUER_CERTIFICATE_2_FILE;
        default:
            return std::string();
    }
}

// Full on-disk path for a File object instance, or "" if it isn't one of the 4.
static std::string ScCertFilePath(const uint32_t fileInstance) {
    const std::string relative = ScCertFileRelativePath(fileInstance);
    if (relative.empty()) {
        return std::string();
    }
    return g_scCertDir + "/" + relative;
}

// Stats the file for a File object instance. Returns false (leaving *size/*mtime
// untouched) if it isn't one of the 4 File objects or the file can't be stat'd
// (e.g. --sc-cert-dir doesn't have it yet - same "certs missing" case ScTransport
// already handles for the listener).
static bool StatScCertFile(const uint32_t fileInstance, long* size, time_t* mtime) {
    // CertStore answers for the staged copy while a certificate procedure is
    // in progress (see cert_store.h), otherwise for the file on disk.
    return IsScCertFileInstance(fileInstance) && CertStore::Stat(fileInstance, size, mtime);
}

// REAL (floating point) - the Analog Input's Present_Value.
bool GetPropertyReal(const uint32_t deviceInstance, const uint16_t objectType,
                     const uint32_t objectInstance, const uint32_t propertyIdentifier,
                     float* value, const bool useArrayIndex,
                     const uint32_t propertyArrayIndex, uint32_t* errorCode) {
    (void)errorCode;   // see "THE errorCode OUT-PARAMETER" above: we decline without naming an error
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    if (deviceInstance != g_deviceInstance) {
        return false;
    }
    if (objectType == OBJECT_TYPE_ANALOG_INPUT &&
        objectInstance == ANALOG_INPUT_INSTANCE &&
        propertyIdentifier == PROPERTY_IDENTIFIER_PRESENT_VALUE) {
        // ON REAL HARDWARE: return the live sensor reading here. Read it from a
        // cached variable that your hardware updates (as g_analogInput1Value is),
        // NOT directly from a slow/blocking device (I2C, SPI, ADC conversion):
        // this callback runs on the BACnetStack_Tick() thread, so blocking it
        // delays all BACnet processing. Sample the sensor on a timer/another
        // thread and just hand back the latest value from here.
        *value = g_analogInput1Value;
        return true;
    }
    return false;
}

// ENUMERATED - the Analog Input's Units (degrees Celsius).
bool GetPropertyEnumerated(const uint32_t deviceInstance, const uint16_t objectType,
                           const uint32_t objectInstance, const uint32_t propertyIdentifier,
                           uint32_t* value, const bool useArrayIndex,
                           const uint32_t propertyArrayIndex, uint32_t* errorCode) {
    (void)errorCode;
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    if (deviceInstance != g_deviceInstance) {
        return false;
    }
    if (propertyIdentifier == PROPERTY_IDENTIFIER_UNITS &&
        objectType == OBJECT_TYPE_ANALOG_INPUT && objectInstance == ANALOG_INPUT_INSTANCE) {
        *value = ENGINEERING_UNITS_DEGREES_CELSIUS;
        return true;
    }
    if (objectType == OBJECT_TYPE_NETWORK_PORT &&
        propertyIdentifier == PROPERTY_IDENTIFIER_BACNET_IP_MODE &&
        objectInstance == NETWORK_PORT_INSTANCE) {
        *value = BACNET_IP_MODE_NORMAL; // not foreign-device, not BBMD
        return true;
    }
    return false;
}

// UNSIGNED INTEGER - the Device's Vendor_Identifier (the stack also uses it to
// build I-Am).
bool GetPropertyUnsignedInteger(const uint32_t deviceInstance, const uint16_t objectType,
                                const uint32_t objectInstance, const uint32_t propertyIdentifier,
                                uint32_t* value, const bool useArrayIndex,
                                const uint32_t propertyArrayIndex, uint32_t* errorCode) {
    (void)errorCode;
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    if (deviceInstance != g_deviceInstance) {
        return false;
    }
    if (objectType == OBJECT_TYPE_DEVICE && objectInstance == g_deviceInstance &&
        propertyIdentifier == PROPERTY_IDENTIFIER_VENDOR_IDENTIFIER) {
        *value = VENDOR_IDENTIFIER;
        return true;
    }
    if (objectType == OBJECT_TYPE_NETWORK_PORT && objectInstance == NETWORK_PORT_INSTANCE) {
        if (propertyIdentifier == PROPERTY_IDENTIFIER_APDU_LENGTH) {
            *value = MAX_APDU_LENGTH;
            return true;
        }
        if (propertyIdentifier == PROPERTY_IDENTIFIER_REFERENCE_PORT) {
            *value = NETWORK_PORT_REFERENCE_PORT_NONE;
            return true;
        }
        if (propertyIdentifier == PROPERTY_IDENTIFIER_BACNET_IP_UDP_PORT) {
            *value = g_bacnetIpUdpPort;
            return true;
        }
    }
    // File_Size (required; no stack default) - the real on-disk byte count of the
    // file this File object serves, so it always agrees with what
    // RegisterCallbackReadFile (section 2d) actually returns. If the cert file is
    // missing (StatScCertFile fails), decline without an error code (see the
    // errorCode-out-parameter note at the top of this file) rather than claim 0 -
    // the stack falls back to its own generic default.
    if (objectType == OBJECT_TYPE_FILE && propertyIdentifier == PROPERTY_IDENTIFIER_FILE_SIZE) {
        long size = 0;
        time_t mtime = 0;
        if (StatScCertFile(objectInstance, &size, &mtime)) {
            *value = (uint32_t)size;
            return true;
        }
        return false;
    }
    return false;
}

// BOOLEAN - Out_Of_Service is a required property of every input object and of
// each Network Port. This is a read-only sensor, so nothing is ever out of
// service: always false.
bool GetPropertyBool(const uint32_t deviceInstance, const uint16_t objectType,
                     const uint32_t objectInstance, const uint32_t propertyIdentifier,
                     bool* value, const bool useArrayIndex,
                     const uint32_t propertyArrayIndex, uint32_t* errorCode) {
    (void)errorCode;
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    if (deviceInstance != g_deviceInstance) {
        return false;
    }
    if (propertyIdentifier == PROPERTY_IDENTIFIER_OUT_OF_SERVICE &&
        (objectType == OBJECT_TYPE_ANALOG_INPUT ||
         objectType == OBJECT_TYPE_NETWORK_PORT)) {
        *value = false;
        return true;
    }
    // Archive / Read_Only (both required; no stack default). Read_Only mirrors the
    // isWritable given to BACnetStack_AddFileObject: the operational and issuer
    // certificate files are writable (clause 19.8.3 certificate procedures), the
    // Certificate Signing Request is not. Archive is never set by this device.
    if (objectType == OBJECT_TYPE_FILE && IsScCertFileInstance(objectInstance)) {
        if (propertyIdentifier == PROPERTY_IDENTIFIER_ARCHIVE) {
            *value = false;
            return true;
        }
        if (propertyIdentifier == PROPERTY_IDENTIFIER_READ_ONLY) {
            *value = (objectInstance == FILE_CSR_INSTANCE);
            return true;
        }
    }
    return false;
}

// DATE / TIME - together they answer Modification_Date (BACnetDateTime), the
// only Date/Time-typed property this device serves; the stack calls both
// callbacks with propertyIdentifier == PROPERTY_IDENTIFIER_MODIFICATION_DATE for
// the one BACnetDateTime read. No other object in this device has a Date- or
// Time-typed property, so these two callbacks exist only for the 4 File objects.
// Required; no stack default (property-profile-reference.md's File section) -
// the real on-disk mtime of the file this File object serves, in UTC.
bool GetPropertyDate(const uint32_t deviceInstance, const uint16_t objectType,
                     const uint32_t objectInstance, const uint32_t propertyIdentifier,
                     uint8_t* yearMinus1900, uint8_t* month, uint8_t* day, uint8_t* weekday,
                     const bool useArrayIndex, const uint32_t propertyArrayIndex, uint32_t* errorCode) {
    (void)errorCode;
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    if (deviceInstance != g_deviceInstance || objectType != OBJECT_TYPE_FILE ||
        propertyIdentifier != PROPERTY_IDENTIFIER_MODIFICATION_DATE) {
        return false;
    }
    long size = 0;
    time_t mtime = 0;
    if (!StatScCertFile(objectInstance, &size, &mtime)) {
        return false;
    }
    struct tm utc;
#if defined(_WIN32)
    gmtime_s(&utc, &mtime);
#else
    gmtime_r(&mtime, &utc);
#endif
    *yearMinus1900 = (uint8_t)utc.tm_year; // struct tm's tm_year is already "years since 1900"
    *month = (uint8_t)(utc.tm_mon + 1);    // struct tm's tm_mon is 0-based; BACnet's Month is 1-based
    *day = (uint8_t)utc.tm_mday;
    *weekday = (uint8_t)(utc.tm_wday == 0 ? 7 : utc.tm_wday); // BACnet Weekday: Monday=1..Sunday=7
    return true;
}

bool GetPropertyTime(const uint32_t deviceInstance, const uint16_t objectType,
                     const uint32_t objectInstance, const uint32_t propertyIdentifier,
                     uint8_t* hour, uint8_t* minute, uint8_t* second, uint8_t* hundredthSecond,
                     const bool useArrayIndex, const uint32_t propertyArrayIndex, uint32_t* errorCode) {
    (void)errorCode;
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    if (deviceInstance != g_deviceInstance || objectType != OBJECT_TYPE_FILE ||
        propertyIdentifier != PROPERTY_IDENTIFIER_MODIFICATION_DATE) {
        return false;
    }
    long size = 0;
    time_t mtime = 0;
    if (!StatScCertFile(objectInstance, &size, &mtime)) {
        return false;
    }
    struct tm utc;
#if defined(_WIN32)
    gmtime_s(&utc, &mtime);
#else
    gmtime_r(&mtime, &utc);
#endif
    *hour = (uint8_t)utc.tm_hour;
    *minute = (uint8_t)utc.tm_min;
    *second = (uint8_t)utc.tm_sec;
    *hundredthSecond = 0; // struct tm has no sub-second resolution
    return true;
}

// OCTET STRING - the BACnet/IP Network Port's addressing. The stack cannot know
// the host's IP, so the application must supply IP_Address and IP_Subnet_Mask
// (and IP_Default_Gateway). Each is four octets. The stack also reads IP_Address
// (with BACnet_IP_UDP_Port) to build the port's six-octet MAC_Address.
bool GetPropertyOctetString(const uint32_t deviceInstance, const uint16_t objectType,
                            const uint32_t objectInstance, const uint32_t propertyIdentifier,
                            uint8_t* value, uint32_t* valueElementCount,
                            const uint32_t maxElementCount, const bool useArrayIndex,
                            const uint32_t propertyArrayIndex, uint32_t* errorCode) {
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    (void)errorCode;
    if (deviceInstance != g_deviceInstance ||
        objectType != OBJECT_TYPE_NETWORK_PORT ||
        objectInstance != NETWORK_PORT_INSTANCE ||
        maxElementCount < 4) {
        return false;
    }
    const uint8_t* source = NULL;
    switch (propertyIdentifier) {
        case PROPERTY_IDENTIFIER_IP_ADDRESS:         source = g_ipAddress; break;
        case PROPERTY_IDENTIFIER_IP_SUBNET_MASK:     source = g_ipSubnetMask; break;
        case PROPERTY_IDENTIFIER_IP_DEFAULT_GATEWAY: source = g_ipDefaultGateway; break;
        default: return false;
    }
    memcpy(value, source, 4);
    *valueElementCount = 4;
    return true;
}


// Small helper: copy a C string into the stack's character-string buffer and
// set the element count + encoding. Returns true (so callers can `return`).
// Description (optional property) of each object: what it is for in this
// example. Kept under ~250 characters - a longer string than the stack's
// character-string buffer aborts the read instead of truncating (found on
// B-BC). Returns "" for an object this device doesn't have.
static std::string ObjectDescription(const uint16_t objectType, const uint32_t objectInstance) {
    if (objectType == OBJECT_TYPE_DEVICE && objectInstance == g_deviceInstance) {
        return std::string("Chipkin CAS BACnet Stack example: a BACnet/SC hub (B-SCHUB profile) with an "
                           "always-on BACnet/IP port. Source, manual and releases: ") + PROJECT_URL;
    }
    if (objectType == OBJECT_TYPE_ANALOG_INPUT && objectInstance == ANALOG_INPUT_INSTANCE) {
        return "Example sensor value in degrees C, showing a hub serving its own data. "
               "Change it with the up/down arrow keys in the console.";
    }
    if (objectType == OBJECT_TYPE_NETWORK_PORT && objectInstance == NETWORK_PORT_INSTANCE) {
        return "BACnet/IP port (UDP). Always on, so this hub can be found and managed over plain BACnet/IP.";
    }
    if (objectType == OBJECT_TYPE_NETWORK_PORT && objectInstance == SC_NETWORK_PORT_INSTANCE) {
        return "BACnet/SC port: the hub function (wss:// listener that devices connect to) and, if "
               "configured, the hub connector. Its certificates are File objects 1-4.";
    }
    if (objectType == OBJECT_TYPE_FILE) {
        switch (objectInstance) {
            case FILE_OPERATIONAL_CERT_INSTANCE:
                return "This hub's operational certificate (PEM), presented in every BACnet/SC TLS "
                       "handshake. Replace it over BACnet (clause 19.8.3), then ACTIVATE_CHANGES.";
            case FILE_CSR_INSTANCE:
                return "Certificate signing request (PEM) for this hub's private key. Have your CA sign "
                       "it, then write the certificate to File 1.";
            case FILE_ISSUER_CERT_1_INSTANCE:
                return "Issuer (CA) certificate, slot 1 (PEM). Devices connecting to this hub must be "
                       "signed by the issuer in slot 1 or slot 2.";
            case FILE_ISSUER_CERT_2_INSTANCE:
                return "Issuer (CA) certificate, slot 2 (PEM). Write a second CA here to trust it "
                       "alongside slot 1. Shows slot 1's certificate until one is written.";
            default:
                break;
        }
    }
    return std::string();
}

static bool ReturnCharacterString(const char* text, char* value,
                                  uint32_t* valueElementCount,
                                  const uint32_t maxElementCount,
                                  uint8_t* encodingType) {
    uint32_t length = (uint32_t)strlen(text);
    if (length > maxElementCount) {
        length = maxElementCount; // see the equivalent B-SS comment: this never
                                   // trips at the default MAX_CHARACTER_STRING_SIZE
    }
    memcpy(value, text, length);
    *valueElementCount = length;
    *encodingType = CHARACTER_STRING_ENCODING_UTF8;
    return true;
}

// CHARACTER STRING - Object_Name for each object, and the device Description.
bool GetPropertyCharString(const uint32_t deviceInstance, const uint16_t objectType,
                           const uint32_t objectInstance, const uint32_t propertyIdentifier,
                           char* value, uint32_t* valueElementCount,
                           const uint32_t maxElementCount, uint8_t* encodingType,
                           const bool useArrayIndex, const uint32_t propertyArrayIndex,
                           uint32_t* errorCode) {
    if (deviceInstance != g_deviceInstance) {
        return false;
    }

    (void)useArrayIndex;
    (void)propertyArrayIndex;
    (void)errorCode;

    // Description (optional, enabled on every object in main()) - what each
    // object is for in this example. See ObjectDescription().
    if (propertyIdentifier == PROPERTY_IDENTIFIER_DESCRIPTION) {
        const std::string description = ObjectDescription(objectType, objectInstance);
        if (!description.empty()) {
            return ReturnCharacterString(description.c_str(), value, valueElementCount, maxElementCount, encodingType);
        }
    }

    // Object_Name - a colour name for the Device/sensor objects (this series'
    // convention); a purpose name for the Network Ports and File objects
    // (deliberately not a colour - see the file header note).
    if (propertyIdentifier == PROPERTY_IDENTIFIER_OBJECT_NAME) {
        if (objectType == OBJECT_TYPE_DEVICE && objectInstance == g_deviceInstance) {
            return ReturnCharacterString(g_deviceName.c_str(), value, valueElementCount, maxElementCount, encodingType);
        }
        if (objectType == OBJECT_TYPE_ANALOG_INPUT && objectInstance == ANALOG_INPUT_INSTANCE) {
            return ReturnCharacterString("Bronze", value, valueElementCount, maxElementCount, encodingType);
        }
        if (objectType == OBJECT_TYPE_NETWORK_PORT && objectInstance == NETWORK_PORT_INSTANCE) {
            return ReturnCharacterString("BACnet IP", value, valueElementCount, maxElementCount, encodingType);
        }
        if (objectType == OBJECT_TYPE_NETWORK_PORT && objectInstance == SC_NETWORK_PORT_INSTANCE) {
            return ReturnCharacterString("BACnet SC", value, valueElementCount, maxElementCount, encodingType);
        }
        if (objectType == OBJECT_TYPE_FILE) {
            switch (objectInstance) {
                case FILE_OPERATIONAL_CERT_INSTANCE: return ReturnCharacterString("Operational Certificate", value, valueElementCount, maxElementCount, encodingType);
                case FILE_CSR_INSTANCE:               return ReturnCharacterString("Certificate Signing Request", value, valueElementCount, maxElementCount, encodingType);
                case FILE_ISSUER_CERT_1_INSTANCE:     return ReturnCharacterString("Issuer Certificate Slot 1", value, valueElementCount, maxElementCount, encodingType);
                case FILE_ISSUER_CERT_2_INSTANCE:     return ReturnCharacterString("Issuer Certificate Slot 2", value, valueElementCount, maxElementCount, encodingType);
                default: break;
            }
        }
    }

    // File_Type (required; no stack default - property-profile-reference.md's File
    // section) - all 4 File objects hold PEM text (certificates/CSR), never the key.
    if (propertyIdentifier == PROPERTY_IDENTIFIER_FILE_TYPE && objectType == OBJECT_TYPE_FILE &&
        IsScCertFileInstance(objectInstance)) {
        return ReturnCharacterString("application/x-pem-file", value, valueElementCount, maxElementCount, encodingType);
    }

    // The remaining strings are all on the Device object - its identity, read
    // by clients and used to populate the device's I-Am / object list.
    if (objectType == OBJECT_TYPE_DEVICE && objectInstance == g_deviceInstance) {
        switch (propertyIdentifier) {
            case PROPERTY_IDENTIFIER_VENDOR_NAME:
                return ReturnCharacterString(VENDOR_NAME, value, valueElementCount, maxElementCount, encodingType);
            case PROPERTY_IDENTIFIER_MODEL_NAME:
                return ReturnCharacterString(MODEL_NAME, value, valueElementCount, maxElementCount, encodingType);
            case PROPERTY_IDENTIFIER_FIRMWARE_REVISION:
                return ReturnCharacterString(g_firmwareRevision.c_str(), value, valueElementCount, maxElementCount, encodingType);
            case PROPERTY_IDENTIFIER_APPLICATION_SOFTWARE_VERSION:
                return ReturnCharacterString(APP_VERSION, value, valueElementCount, maxElementCount, encodingType);
            default:
                break;
        }
    }

    return false;
}

// -----------------------------------------------------------------------------
// 2b. DeviceCommunicationControl callback (DM-DCC-B) - identical pattern to
// B-ASC, which defines it for the series.
//
// A management station sends DeviceCommunicationControl to tell a device to stop
// or resume communicating - useful to quiet a noisy device during commissioning.
// The CAS BACnet Stack runs the actual enable/disable state machine (and the
// optional re-enable timer) for us; this callback's job is to (a) validate the
// optional password and (b) let the application know what was asked.
//
// NOTE (Protocol_Revision >= 20): the plain "disable" value (1) is DEPRECATED.
// Even if this callback accepts it, the stack rejects the request with
// service-request-denied - the standard now expects "disable-initiation" (2).
// -----------------------------------------------------------------------------
// Password check shared by DeviceCommunicationControl and ReinitializeDevice.
// dcc-password (config file only - see docs/manual.md "Configuration file") guards
// both: "" means no password is required. Compared in constant time
// (CASSc::SecretsEqual - issue #23).
static bool PasswordMatches(const char* password, const size_t passwordLength) {
    if (g_dccPassword[0] == '\0') {
        return true;
    }
    const std::string presented = (password != NULL) ? std::string(password, passwordLength) : std::string();
    return CASSc::SecretsEqual(presented, g_dccPassword);
}

bool DeviceCommunicationControl(const uint32_t deviceInstance, const uint8_t enableDisable,
                                const char* password, const uint8_t passwordLength,
                                const bool useTimeDuration, const uint16_t timeDuration,
                                uint32_t* errorCode) {
    if (deviceInstance != g_deviceInstance) {
        *errorCode = ERROR_CODE_OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED;
        return false;
    }

    if (!PasswordMatches(password, passwordLength)) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                              "DeviceCommunicationControl: REJECTED (password failure)");
        *errorCode = ERROR_CODE_PASSWORD_FAILURE;
        return false;
    }

    const char* action = (enableDisable == DCC_ENABLE) ? "enable (resume communication)" :
                         (enableDisable == DCC_DISABLE) ? "disable (1) - DEPRECATED, the stack will reject this" :
                         (enableDisable == DCC_DISABLE_INITIATION) ? "disable-initiation (keep responding)" :
                         "unknown";
    if (useTimeDuration) {
        printf("DeviceCommunicationControl: %s for %u minute(s)\n", action, timeDuration);
    } else {
        printf("DeviceCommunicationControl: %s (indefinitely)\n", action);
    }
    return true;
}

// -----------------------------------------------------------------------------
// 2c. BACnet/SC transport (NM-SCH-B) - see the file header for the design.
// The stack drives the SC protocol and asks the HOST to actually open, accept
// and close WebSocket(+TLS) connections through these four callbacks; each one
// below is a thin forward to g_scTransport (sc_transport/ScTransport.h). The
// stack owns the URI strings' storage only for the duration of the call, so
// every forward below copies into a std::string before calling into
// ScTransport (which may keep/compare the string afterwards).
// -----------------------------------------------------------------------------

// The stack asks us to OPEN an outbound WebSocket/TLS connection to a URI -
// the hub CONNECTOR/initiator role. Forwards to ScTransport::Connect(), real
// as of this phase (see ScTransport.h's class-header comment) - only reached
// when --sc-hub-uri configured the connector role (see main()'s
// BACnetStack_SetBACnetSCHubConnectorForNetworkPort call). Per plan fact 6,
// this return value is discarded by the stack for the hub-connector path
// anyway; ScTransport::Connect() still returns honestly (true only if the
// connection ATTEMPT actually started - see its own doc comment).
bool CallbackInitiateWebsocket(const char* websocketUri, const uint32_t websocketUriLength) {
    const std::string uri(websocketUri, websocketUriLength);
    return g_scTransport.Connect(uri);
}

// The stack asks us to CLOSE a previously opened connection (an outbound URI,
// per fact 6 - not an accepted-peer "|client=" string; those close via the
// hub function's own peer-eviction path instead).
void CallbackDisconnectWebsocket(const char* websocketUri, const uint32_t websocketUriLength) {
    const std::string uri(websocketUri, websocketUriLength);
    g_scTransport.Disconnect(uri);
}

// The stack asks us to START ACCEPTING inbound WebSocket connections on a URI -
// the hub function's accept role, the one this example actually needs for
// NM-SCH-B. Per plan fact 6 this can fire synchronously from inside
// BACnetStack_AddBACnetSCAcceptUri() (called from main() below) and the stack
// retries every Tick() while this returns false - ScTransport::StartListening()
// already implements exactly that contract (returns false + logs once if the
// certificate files are missing, retried silently after that).
bool CallbackSCStartListening(const char* websocketUri, const uint32_t websocketUriLength) {
    const std::string uri(websocketUri, websocketUriLength);
    return g_scTransport.StartListening(uri);
}

// The stack asks us to STOP accepting inbound connections on a URI.
void CallbackSCStopListening(const char* websocketUri, const uint32_t websocketUriLength) {
    const std::string uri(websocketUri, websocketUriLength);
    g_scTransport.StopListening(uri);
}

// Purely observational: logs every BACnet/SC connection-state transition. Left
// registered so a developer dropping in a real transport can see the state
// machine move once BACnetStack_SetBACnetSCWebSocketStatus starts being called
// for real.
void CallbackBACnetSCStateChange(const uint32_t deviceInstance, const uint32_t networkPortInstance,
                                 const uint8_t stateMachine, const uint8_t previousState,
                                 const uint8_t newState, const char* websocketUri,
                                 const uint32_t websocketUriLength) {
    (void)deviceInstance;
    (void)networkPortInstance;
    printf("BACnet/SC: state machine %u: %u -> %u%s%.*s%s\n",
           stateMachine, previousState, newState,
           websocketUriLength ? " (" : "", (int)websocketUriLength, websocketUri,
           websocketUriLength ? ")" : "");
}

// -----------------------------------------------------------------------------
// 2d. File objects (phase 4) - AtomicReadFile for the 4 certificate/CSR File
// objects Network Port 2's SC certificate properties point at (see
// BACnetStack_SetBACnetSCCertificateFileObjects in main()). NEVER serves
// certs/hub.key - see the file header and each function's own comment below.
// -----------------------------------------------------------------------------

// Serves AtomicReadFile against the 4 File objects above by reading the actual
// bytes of the file ScCertFileRelativePath maps that instance to, straight off
// disk under --sc-cert-dir. Every one of those 4 files is a public certificate
// or a CSR - never the private key (hub.key has no File object at all, so there
// is no fileInstance value that reaches it). Any other File object instance -
// there are none in this device today - falls through to Abort(other), per this
// callback's own doc comment for an unrecognised file.
bool CallbackReadFile(const uint32_t deviceInstance, const uint32_t fileInstance,
                      const uint32_t fileStart, const uint32_t requestedCount,
                      uint8_t* fileData, uint32_t* fileDataLength,
                      const uint32_t maxFileDataLength, bool* endOfFile,
                      uint32_t* errorCode) {
    (void)errorCode; // no case here needs a specific error; unhandled falls through to Abort(other)
    if (deviceInstance != g_deviceInstance) {
        return false;
    }
    // CertStore serves the staged copy while a certificate procedure is in
    // progress (so a client can read back what it just wrote), otherwise the
    // file on disk.
    std::string bytes;
    if (!IsScCertFileInstance(fileInstance) || !CertStore::Read(fileInstance, &bytes)) {
        // Cert file missing under --sc-cert-dir (same condition ScTransport's
        // listener already handles for the TLS side) - Abort(other) rather than a
        // fabricated empty file, so a client sees this failed rather than believing
        // it read a real, empty certificate.
        return false;
    }
    const long totalSize = (long)bytes.size();
    if ((uint32_t)totalSize < fileStart) {
        return false; // fileStart past end-of-file
    }
    uint32_t remaining = (uint32_t)totalSize - fileStart;
    uint32_t toRead = requestedCount < remaining ? requestedCount : remaining;
    if (toRead > maxFileDataLength) {
        toRead = maxFileDataLength; // stream reads are silently clamped, per this
                                     // callback's own doc comment - never abort here
    }
    if (toRead > 0) {
        memcpy(fileData, bytes.data() + fileStart, toRead);
    }
    const size_t bytesRead = toRead;
    *fileDataLength = (uint32_t)bytesRead;
    *endOfFile = (fileStart + bytesRead) >= (uint32_t)totalSize;
    return true;
}

// -----------------------------------------------------------------------------
// 2d-ii. Writing certificates over BACnet (ANSI/ASHRAE 135-2024 clause 19.8.3)
//
// The device-B side of the BACnet/SC certificate procedures - what the CAS
// BACnet Explorer's certificate page drives:
//   1. WriteProperty File_Size = 0 on a certificate File object
//      -> SetPropertyUnsignedInteger below -> CertStore::Resize
//   2. AtomicWriteFile the new PEM certificate into it
//      -> CallbackWriteFile below -> CertStore::Write
//      (the stack sets Network Port 2's Changes_Pending on its own, cl. 12.56.100)
//   3. ReinitializeDevice ACTIVATE_CHANGES (or WARMSTART)
//      -> ReinitializeDevice below: validate, commit to disk, reload TLS.
// Writes are STAGED in CertStore until step 3 - see cert_store.h for why.
// -----------------------------------------------------------------------------

// Only the operational certificate and the two issuer slots are writable; the
// Certificate Signing Request (File 2) is read-only - GENERATE_CSR_FILE isn't available (issue #10).
static bool IsWritableScCertFileInstance(const uint32_t fileInstance) {
    return fileInstance == FILE_OPERATIONAL_CERT_INSTANCE ||
           fileInstance == FILE_ISSUER_CERT_1_INSTANCE ||
           fileInstance == FILE_ISSUER_CERT_2_INSTANCE;
}

bool CallbackWriteFile(const uint32_t deviceInstance, const uint32_t fileInstance,
                       const int32_t fileStart, const uint8_t* fileData,
                       const uint32_t fileDataLength, int32_t* ackFileStart, uint32_t* errorCode) {
    if (deviceInstance != g_deviceInstance || !IsWritableScCertFileInstance(fileInstance)) {
        return false;  // the stack rejects read-only File objects before calling this
    }
    if (!CertStore::Write(fileInstance, fileStart, fileData, fileDataLength, ackFileStart, errorCode)) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                              "AtomicWriteFile File %u at %d (%u octets): REJECTED (error code %u)",
                              fileInstance, fileStart, fileDataLength, *errorCode);
        return false;
    }
    CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                          "AtomicWriteFile File %u: %u octets staged at %d - applied on "
                          "ReinitializeDevice ACTIVATE_CHANGES",
                          fileInstance, fileDataLength, *ackFileStart);
    return true;
}

// WriteProperty on an UNSIGNED property. The only writable one in this device is
// a certificate File object's File_Size (the stack makes it writable for a
// writable stream-access File object): 0 empties the file before a new
// certificate is written into it; a smaller size truncates, a larger one
// extends with zero octets (cl. 12.13.6).
bool SetPropertyUnsignedInteger(const uint32_t deviceInstance, const uint16_t objectType,
                                const uint32_t objectInstance, const uint32_t propertyIdentifier,
                                const uint32_t value, const bool useArrayIndex,
                                const uint32_t propertyArrayIndex, const uint8_t priority,
                                uint32_t* errorCode) {
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    (void)priority;
    if (deviceInstance != g_deviceInstance || objectType != OBJECT_TYPE_FILE ||
        propertyIdentifier != PROPERTY_IDENTIFIER_FILE_SIZE ||
        !IsWritableScCertFileInstance(objectInstance)) {
        return false;  // the stack answers write-access-denied
    }
    if (!CertStore::Resize(objectInstance, value, errorCode)) {
        return false;
    }
    CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                          "WriteProperty File %u File_Size = %u: staged - applied on "
                          "ReinitializeDevice ACTIVATE_CHANGES",
                          objectInstance, value);
    return true;
}

// ReinitializeDevice. This hub only supports the two states the certificate
// procedures use: ACTIVATE_CHANGES and WARMSTART both apply staged certificate
// writes. The stack calls this BEFORE it activates its own pending Network Port
// changes, so refusing here (INVALID_CONFIGURATION_DATA) leaves everything as
// it was - the hub never swaps in certificates it couldn't run on. The process
// is not restarted: "warm start" here means "apply the pending changes".
bool ReinitializeDevice(const uint32_t deviceInstance, const uint32_t reinitializedState,
                        const char* password, const uint32_t passwordLength, uint32_t* errorCode) {
    if (deviceInstance != g_deviceInstance) {
        *errorCode = ERROR_CODE_OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED;
        return false;
    }
    if (!PasswordMatches(password, passwordLength)) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                              "ReinitializeDevice: REJECTED (password failure)");
        *errorCode = ERROR_CODE_PASSWORD_FAILURE;
        return false;
    }
    if (reinitializedState != REINITIALIZE_STATE_ACTIVATE_CHANGES &&
        reinitializedState != REINITIALIZE_STATE_WARMSTART) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                              "ReinitializeDevice: state %u not supported (only WARMSTART and "
                              "ACTIVATE_CHANGES)", reinitializedState);
        *errorCode = ERROR_CODE_OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED;
        return false;
    }
    if (!CertStore::HasStagedChanges()) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                              "ReinitializeDevice %s: no staged certificate changes",
                              reinitializedState == REINITIALIZE_STATE_WARMSTART ? "WARMSTART" : "ACTIVATE_CHANGES");
        return true;
    }
    std::string reason;
    if (!CertStore::ValidateStaged(&reason)) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                              "ReinitializeDevice: staged certificates REJECTED, nothing changed: %s",
                              reason.c_str());
        *errorCode = ERROR_CODE_INVALID_CONFIGURATION_DATA;
        return false;
    }
    if (!CertStore::CommitStaged(&reason)) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Error,
                              "ReinitializeDevice: could not save the new certificates: %s", reason.c_str());
        *errorCode = ERROR_CODE_INVALID_CONFIGURATION_DATA;
        return false;
    }
    // Refresh what TLS trusts now, before the stack activates its pending
    // changes - it may restart the SC port itself, and a restarted listener
    // must load the new issuers.
    if (!CertStore::WriteTrustedIssuerBundle(g_scTrustedIssuersPath, &reason)) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Error,
                              "could not refresh \"%s\": %s", g_scTrustedIssuersPath.c_str(), reason.c_str());
    }
    CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                          "ReinitializeDevice: new certificates saved; reloading BACnet/SC TLS");
    g_scReloadCredentialsRequested = true;  // done in the main loop, outside the stack's callback
    return true;
}

// -----------------------------------------------------------------------------
// 2e. Health/metrics (Task 2's 'm' keypress and Task 3's HTTP endpoint) and
// the certificate-upload slot table (Task 4's HTTP endpoint). Both reuse
// existing state: ScCertFileRelativePath (2a-i) for the slot table, and
// g_scTransport's own counters (ScTransport::GetMetrics(), this batch) for
// everything BACnet/SC-related - nothing here invents a second bookkeeping
// scheme.
// -----------------------------------------------------------------------------

// Maps a cert-upload slot name (POST /certs/<slot>) to its File object instance
// - an HTTP client has no reason to know this device's object numbering.
// Returns 0 for an unrecognised slot.
static uint32_t CertUploadSlotInstance(const std::string& slot) {
    if (slot == "operational") return FILE_OPERATIONAL_CERT_INSTANCE;
    if (slot == "csr") return FILE_CSR_INSTANCE;
    if (slot == "issuer1") return FILE_ISSUER_CERT_1_INSTANCE;
    if (slot == "issuer2") return FILE_ISSUER_CERT_2_INSTANCE;
    return 0;
}

// HttpServer's slot check: known slot -> the file it replaces (for its logs).
static bool ResolveCertUploadSlot(const std::string& slot, std::string* outRelativeFilename) {
    const uint32_t fileInstance = CertUploadSlotInstance(slot);
    *outRelativeFilename = fileInstance != 0 ? ScCertFileRelativePath(fileInstance) : std::string();
    return !outRelativeFilename->empty();
}

// Installs a POST /certs/<slot> upload (issue #25) the same way a certificate
// written over BACnet is activated (section 2d-ii): stage it in CertStore,
// ValidateStaged() the resulting set, and only then commit it and reload TLS.
// So an upload that doesn't parse, or that would leave the hub unable to run
// BACnet/SC (a certificate for another key, one that doesn't chain to an
// issuer, no issuer left), is refused and nothing on disk changes. The CSR
// slot is checked to be a valid request for this hub's key. Returns the HTTP
// status for HttpServer to answer with.
static int ApplyCertUpload(const std::string& slot, const std::string& body, std::string* message) {
    const uint32_t fileInstance = CertUploadSlotInstance(slot);
    if (fileInstance == FILE_CSR_INSTANCE) {
        if (!CertStore::InstallCertificateSigningRequest(fileInstance, body, message)) {
            return 400;
        }
        *message = "certificate signing request replaced";
        return 200;
    }
    if (CertStore::HasStagedChanges()) {
        // Don't mix an upload into a BACnet certificate procedure in progress.
        *message = "a certificate change made over BACnet is waiting for ReinitializeDevice ACTIVATE_CHANGES; "
                   "activate it (or restart the hub to drop it) first";
        return 409;
    }
    uint32_t errorCode = 0;
    if (!CertStore::StageWholeFile(fileInstance, body, &errorCode)) {
        CertStore::DiscardStaged();
        *message = "could not stage the file (BACnet error code " + std::to_string(errorCode) + ")";
        return 400;
    }
    std::string reason;
    if (!CertStore::ValidateStaged(&reason)) {
        CertStore::DiscardStaged();
        *message = reason;
        return 400;
    }
    if (!CertStore::CommitStaged(&reason)) {
        CertStore::DiscardStaged();
        *message = "could not save it: " + reason;
        return 500;
    }
    if (!CertStore::WriteTrustedIssuerBundle(g_scTrustedIssuersPath, &reason)) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Error,
                              "could not refresh \"%s\": %s", g_scTrustedIssuersPath.c_str(), reason.c_str());
    }
    g_scReloadCredentialsRequested = true;  // the main loop reloads BACnet/SC TLS
    *message = "validated and saved; reloading BACnet/SC TLS";
    return 200;
}

// Formats a byte count of elapsed steady-clock time// Formats a byte count of elapsed steady-clock time as "NdNNhNNmNNs" (only
// the units actually needed - no leading "0d0h" for a device that has been up
// 5 minutes). Shared by the 'm' keypress (plain text) and the HTTP JSON body
// (as both a human string and a raw seconds count, so a monitoring scraper
// does not have to parse the string).
static uint64_t UptimeSeconds() {
    const auto elapsed = std::chrono::steady_clock::now() - g_startTime;
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
}

static std::string FormatUptime(const uint64_t totalSeconds) {
    const uint64_t days = totalSeconds / 86400;
    const uint64_t hours = (totalSeconds % 86400) / 3600;
    const uint64_t minutes = (totalSeconds % 3600) / 60;
    const uint64_t seconds = totalSeconds % 60;
    char buf[64];
    if (days > 0) {
        snprintf(buf, sizeof(buf), "%llud %lluh %llum %llus",
                 (unsigned long long)days, (unsigned long long)hours,
                 (unsigned long long)minutes, (unsigned long long)seconds);
    } else if (hours > 0) {
        snprintf(buf, sizeof(buf), "%lluh %llum %llus",
                 (unsigned long long)hours, (unsigned long long)minutes, (unsigned long long)seconds);
    } else {
        snprintf(buf, sizeof(buf), "%llum %llus", (unsigned long long)minutes, (unsigned long long)seconds);
    }
    return std::string(buf);
}

// GET /metrics - the counters: uptime, BACnet/SC connections, rate-limit
// rejections, RX/TX. The SAME numbers PrintHealthSnapshot() prints for the
// 'm' keypress, read from the same place (g_scTransport.GetMetrics()). Plain
// hand-built JSON - the shape is flat enough that a JSON library isn't worth
// the dependency.
static std::string BuildMetricsJson() {
    const CASSc::ScTransportMetrics m = g_scTransport.GetMetrics();
    const uint64_t uptime = UptimeSeconds();
    char buf[768];
    snprintf(buf, sizeof(buf),
        "{"
        "\"uptime_seconds\":%llu,"
        "\"uptime\":\"%s\","
        "\"sc_hub_connections_current\":%zu,"
        "\"sc_hub_connections_max\":%u,"
        "\"sc_total_connects\":%llu,"
        "\"sc_total_disconnects\":%llu,"
        "\"sc_rate_limit_rejections\":%llu,"
        "\"sc_rx_messages\":%llu,"
        "\"sc_rx_bytes\":%llu,"
        "\"sc_tx_messages\":%llu,"
        "\"sc_tx_bytes\":%llu,"
        "\"sc_tx_queue_overflows\":%llu"
        "}",
        (unsigned long long)uptime, FormatUptime(uptime).c_str(),
        m.currentPeerCount, (unsigned)g_scMaxHubConnections,
        (unsigned long long)m.totalConnects, (unsigned long long)m.totalDisconnects,
        (unsigned long long)m.rateLimitRejections,
        (unsigned long long)m.rxMessages, (unsigned long long)m.rxBytes,
        (unsigned long long)m.txMessages, (unsigned long long)m.txBytes,
        (unsigned long long)m.txQueueOverflows);
    return std::string(buf);
}

// GET /health - is the hub doing its job? "ok" (HTTP 200) when the BACnet/SC
// hub function is listening; "degraded" (HTTP 503) when it isn't - most often
// because the certificates in --sc-cert-dir are missing or unusable. BACnet/IP
// keeps working either way. Deliberately small: a monitor polls it often.
static std::string BuildHealthJson(bool* healthy) {
    const bool listening = g_scTransport.IsListening();
    *healthy = listening;
    char buf[512];
    snprintf(buf, sizeof(buf),
        "{"
        "\"status\":\"%s\","
        "\"version\":\"%s\","
        "\"uptime_seconds\":%llu,"
        "\"bacnet_ip_enabled\":%s,"
        "\"sc_hub_function_listening\":%s,"
        "\"sc_hub_connections_current\":%zu,"
        "\"staged_certificate_changes\":%s"
        "}",
        listening ? "ok" : "degraded", APP_VERSION, (unsigned long long)UptimeSeconds(),
        g_bacnetIpEnabled ? "true" : "false", listening ? "true" : "false", g_scTransport.GetMetrics().currentPeerCount,
        CertStore::HasStagedChanges() ? "true" : "false");
    return std::string(buf);
}

// HTML-escapes text for the status page (every value on it is built by this
// program, but a URI or name could still contain '<' or '&').
static std::string HtmlEscape(const std::string& s) {
    std::string out;
    for (const char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            default: out += c; break;
        }
    }
    return out;
}

// The page GET / serves: what is running (example, stack and common/
// versions, device), BACnet/SC status, and the health/metrics numbers - the
// SAME metrics GET /health and GET /metrics return, shown as a table and as
// links to both endpoints, the project and the stack product page.
// Server-rendered, no JavaScript, no external resources; refreshes every 5 s.
static std::string BuildStatusPage() {
    const CASSc::ScTransportMetrics m = g_scTransport.GetMetrics();
    const uint64_t uptime = UptimeSeconds();
    bool healthy = true;
    BuildHealthJson(&healthy);

    struct Row { const char* label; std::string value; };
    char n[64];
    auto num = [&n](unsigned long long v) { snprintf(n, sizeof(n), "%llu", v); return std::string(n); };
    const Row version[] = {
        {"Example", std::string(APP_NAME) + " v" + APP_VERSION},
        {"CAS BACnet Stack", g_firmwareRevision},
        {"Common helper (common/)", CASExampleHelper::COMMON_VERSION},
        {"Device", g_deviceName + " (instance " + num(g_deviceInstance) + ")"},
    };
    const Row sc[] = {
        {"Health", healthy ? std::string("ok")
                           : g_bacnetIpEnabled ? std::string("degraded - the BACnet/SC hub function is not listening")
                                               : std::string("degraded - BACnet/SC is not listening and BACnet/IP "
                                                             "is off: unreachable over BACnet")},
        {"BACnet/IP", g_bacnetIpEnabled ? "on, UDP port " + std::to_string(g_bacnetIpUdpPort)
                                        : std::string("off (BACnet/SC only)")},
        {"Hub function (listener)", g_scTransport.IsListening() ? "listening on " + g_scTransport.ListenUri() : "not listening"},
        {"Hub connector", g_scHubUri.empty() ? std::string("off") : "dialing " + g_scHubUri},
        {"Certificate revocation list", FileFingerprint(g_scCrlPath).empty()
            ? std::string("none (revocation not checked)") : g_scCrlPath},
        {"Staged certificate changes", CertStore::HasStagedChanges()
            ? std::string("yes - applied on ReinitializeDevice ACTIVATE_CHANGES") : std::string("none")},
    };
    const Row metrics[] = {
        {"Uptime", FormatUptime(uptime)},
        {"Hub connections (current / max)", num(m.currentPeerCount) + " / " + num(g_scMaxHubConnections)},
        {"Connects (total)", num(m.totalConnects)},
        {"Disconnects (total)", num(m.totalDisconnects)},
        {"Rate-limit rejections", num(m.rateLimitRejections)},
        {"RX", num(m.rxMessages) + " messages, " + num(m.rxBytes) + " bytes"},
        {"TX", num(m.txMessages) + " messages, " + num(m.txBytes) + " bytes"},
        {"Closed with a full transmit queue", num(m.txQueueOverflows)},
    };

    std::string html;
    html += "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta http-equiv=\"refresh\" content=\"5\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>B-SCHUB status</title><style>"
            "body{font-family:system-ui,sans-serif;margin:24px;max-width:760px;color:#1f2328;background:#fff}"
            "h1{font-size:1.4em;margin:0 0 4px}h2{font-size:1.05em;margin:24px 0 8px}"
            "p.sub{margin:0;color:#59636e}table{border-collapse:collapse;width:100%}"
            "td{padding:6px 8px;border-bottom:1px solid #d1d9e0;vertical-align:top}"
            "td:first-child{color:#59636e;width:42%}pre{background:#f6f8fa;padding:12px;overflow-x:auto}"
            "@media (prefers-color-scheme:dark){body{color:#e6edf3;background:#0d1117}"
            "p.sub,td:first-child{color:#9198a1}td{border-color:#3d444d}pre{background:#161b22}a{color:#4493f8}}"
            "</style></head><body>\n";
    html += "<h1>" + HtmlEscape(g_deviceName) + "</h1><p class=\"sub\">Version " + HtmlEscape(APP_VERSION) +
            " &middot; BACnet/SC hub &middot; refreshes every 5 s</p>\n";
    auto table = [&html](const char* title, const Row* rows, size_t count) {
        html += std::string("<h2>") + title + "</h2><table>";
        for (size_t i = 0; i < count; ++i) {
            html += "<tr><td>" + HtmlEscape(rows[i].label) + "</td><td>" + HtmlEscape(rows[i].value) + "</td></tr>";
        }
        html += "</table>\n";
    };
    table("Version", version, sizeof(version) / sizeof(version[0]));
    table("BACnet/SC", sc, sizeof(sc) / sizeof(sc[0]));
    table("Health and metrics", metrics, sizeof(metrics) / sizeof(metrics[0]));

    // Connected devices (issue #21): who each accepted socket is - its
    // address, the certificate it presented, and its BACnet/SC VMAC and UUID.
    const std::vector<CASSc::ScPeerInfo> peers = g_scTransport.GetPeers();
    html += "<h2>Connected devices</h2>";
    if (peers.empty()) {
        html += "<p class=\"sub\">None.</p>\n";
    } else {
        html += "<table>";
        for (const CASSc::ScPeerInfo& peer : peers) {
            const std::string identity = peer.uuid.empty()
                ? std::string("waiting for its Connect-Request")
                : "VMAC " + peer.vmac + ", UUID " + peer.uuid + (peer.accepted ? "" : " (not accepted)");
            html += "<tr><td>" + HtmlEscape(peer.address) + "</td><td>" + HtmlEscape(peer.certificateSubject) +
                    "<br>" + HtmlEscape(identity) + "</td></tr>";
        }
        html += "</table>\n";
    }
    html += "<h2>Endpoints</h2><table>"
            "<tr><td><a href=\"/health\">/health</a></td><td>Is the hub working? JSON; HTTP 200 when ok, "
            "503 when degraded.</td></tr>"
            "<tr><td><a href=\"/metrics\">/metrics</a></td><td>Uptime, connection and traffic counters. "
            "JSON.</td></tr></table>\n";
    html += std::string("<h2>More</h2><table>") +
            "<tr><td>This example</td><td><a href=\"" + PROJECT_URL + "\">" + PROJECT_URL +
            "</a></td></tr>"
            "<tr><td>CAS BACnet Stack</td><td><a href=\"" + STACK_PRODUCT_URL + "\">" + STACK_PRODUCT_URL +
            "</a></td></tr></table>\n";
    html += "</body></html>\n";
    return html;
}

// Plain-text health/metrics snapshot for the 'm' keypress (Task 2) - same
// fields as BuildMetricsJson() above, formatted for a human reading stdout
// rather than a monitoring scraper.
static void PrintHealthSnapshot() {
    const CASSc::ScTransportMetrics m = g_scTransport.GetMetrics();
    const uint64_t uptime = UptimeSeconds();
    printf("--- Health/metrics snapshot -------------------------------------------\n");
    printf("Uptime:                    %s (%llu s)\n", FormatUptime(uptime).c_str(), (unsigned long long)uptime);
    printf("BACnet/SC hub connections: %zu / %u (current / --sc-max-hub-connections)\n",
           m.currentPeerCount, (unsigned)g_scMaxHubConnections);
    printf("BACnet/SC connects total:      %llu\n", (unsigned long long)m.totalConnects);
    printf("BACnet/SC disconnects total:   %llu\n", (unsigned long long)m.totalDisconnects);
    printf("BACnet/SC rate-limit rejects:  %llu\n", (unsigned long long)m.rateLimitRejections);
    printf("BACnet/SC RX: %llu message(s), %llu byte(s)\n",
           (unsigned long long)m.rxMessages, (unsigned long long)m.rxBytes);
    printf("BACnet/SC TX: %llu message(s), %llu byte(s)\n",
           (unsigned long long)m.txMessages, (unsigned long long)m.txBytes);
    printf("BACnet/SC transmit-queue-full closes: %llu\n", (unsigned long long)m.txQueueOverflows);
    printf("------------------------------------------------------------------------\n");
}

// -----------------------------------------------------------------------------
// 2f. libwebsockets logging integration (Item 5 of this batch's diagnostics
// pass). Before this, lws's own internal debug/warning/error lines (e.g.
// "lws_tls_server_accept: client cert CN '...'") printed however lws's build
// default configured them - unformatted, no timestamp, not through
// CASExampleHelper::Log, not controllable independently of this app's own
// log level. lws_set_log_level(level, callback) below routes them through
// the SAME facility every other log line in this batch's diagnostics work
// uses.
//
// Level choice: LLL_ERR | LLL_WARN | LLL_NOTICE - roughly what was already
// visible before this change (lws's own build default is "err, warn, notice"
// per lws_set_log_level's own doc comment in lws-logs.h), so this does not
// silence anything that was already printing. Deliberately NOT LLL_DEBUG/
// LLL_PARSER/etc - those are lws's per-frame/per-byte protocol trace, far too
// noisy for a tutorial's default log output (this app has no --verbose/
// --debug flag to gate a heavier level behind, and adding one is out of
// scope for this batch).
static void LwsLogCallback(int level, const char* line) {
    // lws hands us its own already-formatted line, which may carry a
    // trailing '\n' (and sometimes '\r\n' - observed on Windows builds) -
    // strip it so it does not produce a blank line between lws's text and
    // CASExampleHelper::Log's own trailing '\n', and so lws's text sits
    // cleanly after Log's "<UTC timestamp> [LEVEL] " prefix instead of
    // wrapping onto its own line.
    std::string text(line != nullptr ? line : "");
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
        text.pop_back();
    }
    if (text.empty()) {
        return;
    }
    // LLL_ERR/LLL_WARN map to this app's Error/Warning (both already go to
    // stderr in CASExampleHelper::Log, matching where lws's own default
    // stderr emitter would have put them); everything else this level mask
    // enables (LLL_NOTICE) maps to Info - see this function's own header
    // comment for why DEBUG/PARSER/etc are never enabled in the first place.
    CASExampleHelper::LogLevel mapped = CASExampleHelper::LogLevel::Info;
    if (level & LLL_ERR) {
        mapped = CASExampleHelper::LogLevel::Error;
    } else if (level & LLL_WARN) {
        mapped = CASExampleHelper::LogLevel::Warning;
    }
    CASExampleHelper::Log(mapped, "lws: %s", text.c_str());
}

// -----------------------------------------------------------------------------
// 3. main()
// -----------------------------------------------------------------------------
// Parse "--sc-port <n>" (1..65535); returns defaultPort if not given/invalid.
// Deliberately local to main.cpp, not common/ - see the CLI-args note in the
// file header (common's --help cannot list example-specific options).
static uint16_t ParseScPortArg(const int argc, char** argv, const uint16_t defaultPort) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--sc-port") == 0) {
            char* end = NULL;
            const long value = strtol(argv[i + 1], &end, 10);
            if (end != argv[i + 1] && *end == '\0' && value > 0 && value <= 65535) {
                return (uint16_t)value;
            }
            printf("Warning: ignoring invalid --sc-port \"%s\" (want 1..65535); using %u.\n",
                   argv[i + 1], (unsigned)defaultPort);
        }
    }
    return defaultPort;
}

// Parse "--sc-max-hub-connections <n>" (1..65535); returns defaultValue if not
// given/invalid. A value above SC_MAX_HUB_CONNECTIONS_LIMIT is returned as-is
// so CheckScMaxHubConnectionsLimit() can refuse it loudly.
static uint16_t ParseScMaxHubConnectionsArg(const int argc, char** argv, const uint16_t defaultValue) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--sc-max-hub-connections") == 0) {
            char* end = NULL;
            const long value = strtol(argv[i + 1], &end, 10);
            if (end != argv[i + 1] && *end == '\0' && value > 0 && value <= 65535) {
                return (uint16_t)value;
            }
            printf("Warning: ignoring invalid --sc-max-hub-connections \"%s\" (want 1..65535); using %u.\n",
                   argv[i + 1], (unsigned)defaultValue);
        }
    }
    return defaultValue;
}

// Refuses to start if more than SC_MAX_HUB_CONNECTIONS_LIMIT connections were
// asked for. Deliberately loud: a banner on stdout AND stderr, then exit(1), so
// nobody mistakes this example for a production hub. Returns only if the value
// is within the limit.
static void CheckScMaxHubConnectionsLimit(const uint16_t requested, const char* source) {
    if (requested <= SC_MAX_HUB_CONNECTIONS_LIMIT) {
        return;
    }
    char banner[1600];
    snprintf(banner, sizeof(banner),
             "\n"
             "################################################################################\n"
             "##                                                                            ##\n"
             "##   ERROR: TOO MANY BACnet/SC CONNECTIONS REQUESTED                          ##\n"
             "##                                                                            ##\n"
             "################################################################################\n"
             "\n"
             "  sc-max-hub-connections = %u (from %s)\n"
             "\n"
             "  This example hub accepts at most %u BACnet/SC devices at a time. It is\n"
             "  for evaluation and testing only, not for production use.\n"
             "\n"
             "  For a production BACnet/SC hub with more connections, contact Chipkin:\n"
             "\n"
             "      %s\n"
             "      https://store.chipkin.com/services/stacks/bacnet-stack\n"
             "\n"
             "  To run this example, set sc-max-hub-connections to %u or less.\n"
             "  Shutting down.\n"
             "\n"
             "################################################################################\n"
             "\n",
             (unsigned)requested, source, (unsigned)SC_MAX_HUB_CONNECTIONS_LIMIT, SUPPORT_EMAIL,
             (unsigned)SC_MAX_HUB_CONNECTIONS_LIMIT);
    fputs(banner, stdout);
    fflush(stdout);
    fputs(banner, stderr);
    fflush(stderr);
    exit(1);
}

// Parse "<flagName> <n>" (0..65535; 0 = no limit) for --sc-rate-limit and
// --sc-rate-limit-total; returns defaultValue if not given/invalid. Same
// pattern as ParseScMaxHubConnectionsArg above, except 0 is a valid value.
static uint16_t ParseScRateLimitArg(const int argc, char** argv, const char* flagName, const uint16_t defaultValue) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], flagName) == 0) {
            char* end = NULL;
            const long value = strtol(argv[i + 1], &end, 10);
            if (end != argv[i + 1] && *end == '\0' && value >= 0 && value <= 65535) {
                return (uint16_t)value;
            }
            printf("Warning: ignoring invalid %s \"%s\" (want 0..65535); using %u.\n",
                   flagName, argv[i + 1], (unsigned)defaultValue);
        }
    }
    return defaultValue;
}

// Parse "--http-port <n>" (1..65535); returns defaultPort if not
// given/invalid. Same pattern as ParseScPortArg above (Task 3/4's health,
// metrics and cert-upload HTTP endpoint - see g_httpServer).
static uint16_t ParseHttpPortArg(const int argc, char** argv, const uint16_t defaultPort) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--http-port") == 0) {
            char* end = NULL;
            const long value = strtol(argv[i + 1], &end, 10);
            if (end != argv[i + 1] && *end == '\0' && value > 0 && value <= 65535) {
                return (uint16_t)value;
            }
            printf("Warning: ignoring invalid --http-port \"%s\" (want 1..65535); using %u.\n",
                   argv[i + 1], (unsigned)defaultPort);
        }
    }
    return defaultPort;
}

// Parse "--sc-cert-dir <dir>"; returns defaultDir if not given.
static std::string ParseScCertDirArg(const int argc, char** argv, const std::string& defaultDir) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--sc-cert-dir") == 0) {
            return std::string(argv[i + 1]);
        }
    }
    return defaultDir;
}

// Parse "<flagName> <value>" (e.g. "--sc-hub-uri wss://..."); returns "" if
// not given. Shared by --sc-hub-uri and --sc-failover-uri - both are plain
// "take the next argument verbatim" options (the stack itself rejects a
// malformed URI when BACnetStack_SetBACnetSCHubConnectorForNetworkPort is
// called - no point duplicating that validation here).
static std::string ParseStringArg(const int argc, char** argv, const char* flagName) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], flagName) == 0) {
            return std::string(argv[i + 1]);
        }
    }
    return std::string();
}

// Parse "<flagName> [n]": returns true if the flag is present. *outCount is
// the number after it, or defaultCount when the next argument is missing or
// is another flag (so "--generate-certs" alone means the default). A value
// that is present but not a positive integer is an error (*outValid = false).
static bool ParseOptionalCountArg(const int argc, char** argv, const char* flagName,
                                  const unsigned defaultCount, unsigned* outCount, bool* outValid) {
    *outValid = true;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], flagName) != 0) {
            continue;
        }
        *outCount = defaultCount;
        if (i + 1 < argc && argv[i + 1][0] != '-') {
            char* end = NULL;
            const unsigned long n = strtoul(argv[i + 1], &end, 10);
            if (end == argv[i + 1] || *end != '\0' || n == 0 || n > 999) {
                fprintf(stderr, "Error: %s expects a count from 1 to 999, got \"%s\".\n", flagName, argv[i + 1]);
                *outValid = false;
            } else {
                *outCount = (unsigned)n;
            }
        }
        return true;
    }
    return false;
}

// Parse "<flagName> <n>" with n in minValue..maxValue; returns defaultValue if
// the flag is not given, or (with a warning) if its value is out of range.
static uint32_t ParseUIntArg(const int argc, char** argv, const char* flagName, const uint32_t minValue,
                             const uint32_t maxValue, const uint32_t defaultValue) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], flagName) == 0) {
            char* end = NULL;
            const unsigned long value = strtoul(argv[i + 1], &end, 10);
            if (end != argv[i + 1] && *end == '\0' && value >= minValue && value <= maxValue) {
                return (uint32_t)value;
            }
            printf("Warning: ignoring invalid %s \"%s\" (want %u..%u).\n", flagName, argv[i + 1],
                   (unsigned)minValue, (unsigned)maxValue);
        }
    }
    return defaultValue;
}

static bool HasFlag(const int argc, char** argv, const char* flagName) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], flagName) == 0) {
            return true;
        }
    }
    return false;
}

// The hub itself. main() (at the end of this file) runs it directly, or as a
// Windows service - see service.h.
static int RunHub(int argc, char** argv) {
    // Show printf output immediately, even when stdout is piped to a file.
    setvbuf(stdout, NULL, _IONBF, 0);

    // --- Load the CAS BACnet Stack -------------------------------------------
    if (!LoadBACnetFunctions()) {
        fprintf(stderr, "Error: failed to load the CAS BACnet Stack: %s\n",
                CASBACnetStackAdapter_LastError());
        return 1;
    }

    // g_firmwareRevision (Device object property 44) - see its own doc
    // comment above for why this is the STACK's version, not this example's
    // own (that's Application_Software_Version/APP_VERSION instead). Must
    // happen after LoadBACnetFunctions() (these getters ARE some of the
    // functions it loads) and before the Device object is ever readable.
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                 BACnetStack_GetAPIMajorVersion(), BACnetStack_GetAPIMinorVersion(),
                 BACnetStack_GetAPIPatchVersion(), BACnetStack_GetAPIBuildVersion());
        g_firmwareRevision = buf;
    }

    // --- Command line + version --------------------------------------------
    // showDccPasswordCliOption=false (common/ 2.7.0) - this example does NOT
    // accept --dcc-password on the command line (Task 1: config-file only,
    // see g_dccPassword's own comment and docs/manual.md "Configuration file").
    if (CASExampleHelper::HandleHelpAndVersionArgs(argc, argv, APP_NAME, APP_VERSION,
                                                   /*showDccPasswordCliOption*/ false)) {
        // common/'s --help handler cannot know about this example's BACnet/SC
        // options (see the file header) - print them here too, but only for
        // --help/-h//? (not --version, which HandleHelpAndVersionArgs also
        // handles and which should stay just a version string).
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "/?") == 0) {
                printf("\nDevice and logging:\n");
                printf("  --device-name <name>\n");
                printf("                      The Device's Object_Name - must be unique on the BACnet\n");
                printf("                      internetwork. Default \"%s\".\n", DEVICE_NAME_DEFAULT);
                printf("  --ip-network-number <n>, --sc-network-number <n>\n");
                printf("                      Network_Number (1..65534) of Network Port 1 (BACnet/IP) /\n");
                printf("                      2 (BACnet/SC), reported as configured. Default: not set.\n");
                printf("  --log-file <path>   Also write all console output to this file, rotating it.\n");
                printf("  --log-max-size-mb <n>\n");
                printf("                      Rotate the log file at this size. Default 10.\n");
                printf("  --log-max-files <n> Old log files kept (<path>.1 ... <path>.n). Default 5.\n");
                printf("\nBACnet/IP:\n");
                printf("  --bacnet-ip <on|off>\n");
                printf("                      off = BACnet/SC only: no UDP socket and no Network Port 1;\n");
                printf("                      the device is reachable only over BACnet/SC. Default on.\n");
                printf("\nBACnet/SC options (NM-SCH-B hub function):\n");
                printf("  --sc-port <n>       WebSocket/TLS port for the hub accept URI. Default 47819.\n");
                printf("  --sc-cert-dir <dir> Directory holding operational-certificate.pem,\n");
                printf("                      private-key.pem and issuer-certificate.pem (or the older\n");
                printf("                      hub.crt/hub.key/ca.crt; see\n");
                printf("                      --generate-certs below). Default \"./certs\".\n");
                printf("  --sc-hub-uri <wss://host:port/path>\n");
                printf("                      Also run the hub CONNECTOR role: dial out to another hub at\n");
                printf("                      this URI. Off by default (this example needs only the hub\n");
                printf("                      FUNCTION/listener role above for NM-SCH-B).\n");
                printf("  --sc-failover-uri <wss://host:port/path>\n");
                printf("                      Optional failover hub URI, used only if --sc-hub-uri is\n");
                printf("                      also given.\n");
                printf("  --sc-max-hub-connections <n>\n");
                printf("                      Max BACnet/SC devices connected to the hub at once, 1 to %u.\n",
                       (unsigned)SC_MAX_HUB_CONNECTIONS_LIMIT);
                printf("                      Default %u. This example is limited to %u for evaluation and\n",
                       (unsigned)SC_MAX_HUB_CONNECTIONS_DEFAULT, (unsigned)SC_MAX_HUB_CONNECTIONS_LIMIT);
                printf("                      testing; for production, contact %s.\n", SUPPORT_EMAIL);
                printf("  --sc-rate-limit <n>\n");
                printf("                      Max NEW BACnet/SC connection attempts/second from any one\n");
                printf("                      source address. Excess attempts are refused before the TLS\n");
                printf("                      handshake. 0 = no limit. Default %u.\n", (unsigned)SC_RATE_LIMIT_DEFAULT);
                printf("  --sc-rate-limit-total <n>\n");
                printf("                      Max NEW BACnet/SC connection attempts/second for the whole\n");
                printf("                      listener, all addresses together. 0 = no limit. Default %u.\n",
                       (unsigned)SC_RATE_LIMIT_TOTAL_DEFAULT);
                printf("  --sc-accept-hub-without-hello\n");
                printf("                      Compatibility, off by default: let the hub connector\n");
                printf("                      (--sc-hub-uri) accept a hub whose Connect-Accept omits\n");
                printf("                      the Hello option the standard requires. Deviates from\n");
                printf("                      ANSI/ASHRAE 135 - see docs/manual.md \"BACnet/SC compatibility\".\n");
                printf("\nLab certificates (LAB TESTING ONLY - written to --sc-cert-dir, then exits):\n");
                printf("  --generate-certs [n]\n");
                printf("                      Create a fresh set of PEM files named after the Network\n");
                printf("                      Port properties: issuer-certificate.pem (+ its key), this\n");
                printf("                      hub's operational-certificate.pem, private-key.pem and\n");
                printf("                      certificate-signing-request.pem, and n labeled client\n");
                printf("                      folders, clients/client-01/ ... (each holding its own\n");
                printf("                      operational-certificate.pem, private-key.pem and\n");
                printf("                      issuer-certificate.pem). Default n = 3. Refuses to replace\n");
                printf("                      an existing issuer unless --force is also given.\n");
                printf("  --add-client-certs [n]\n");
                printf("                      Sign n more client certificates (default 1) with the issuer\n");
                printf("                      already in --sc-cert-dir. Numbering continues after the\n");
                printf("                      highest existing label, and the running hub trusts them\n");
                printf("                      without a restart.\n");
                printf("  --cert-label <prefix>\n");
                printf("                      Label for client certificates. Default \"client\", giving\n");
                printf("                      client-01, client-02, ... Each certificate's Common Name is\n");
                printf("                      \"Chipkin Example B-SCHUB <label>-NN\". Every certificate is\n");
                printf("                      also listed in <sc-cert-dir>/certificates.txt.\n");
                printf("  --cert-hub-uri <wss://host:port/>\n");
                printf("                      Primary hub URI written into each client's bacnetsc.config\n");
                printf("                      (CAS BACnet Explorer import file). Default: this\n");
                printf("                      machine's IPv4 address and --sc-port.\n");
                printf("  --force             With --generate-certs: delete the old set first.\n");
                printf("\nHTTP health/metrics + certificate upload (Tasks 3/4):\n");
                printf("  --http-port <n>     TCP port for GET / (status page), the read-only GET /health,\n");
                printf("                      GET /metrics and\n");
                printf("                      POST /certs/<slot> HTTP endpoints. Default 8080.\n");
                printf("                      GET /health and GET /metrics need no authentication.\n");
                printf("                      POST /certs/<slot> (slot: operational, csr, issuer1, issuer2)\n");
                printf("                      requires \"Authorization: Bearer <http-upload-token>\" and\n");
                printf("                      is DISABLED ENTIRELY if http-upload-token is not set - see\n");
                printf("                      docs/manual.md \"Uploading a certificate\".\n");
                printf("  --http-bind <addr>  Interface the HTTP endpoints above bind to. Default\n");
                printf("                      127.0.0.1 (loopback only). Binding anywhere else (e.g.\n");
                printf("                      0.0.0.0, or a LAN address) is a real security tradeoff -\n");
                printf("                      GET /, /health and /metrics have NO authentication, and\n");
                printf("                      without --http-tls it is plain HTTP - see README.md\n");
                printf("                      \"Security\" before setting this to anything else.\n");
                printf("  --http-tls          Serve the HTTP endpoints over HTTPS (TLS 1.2/1.3). Uses the\n");
                printf("                      hub's operational-certificate.pem and private-key.pem\n");
                printf("                      unless --http-tls-cert/--http-tls-key say otherwise.\n");
                printf("  --http-tls-cert <file>, --http-tls-key <file>\n");
                printf("                      Certificate (PEM, may include its chain) and key for --http-tls.\n");
                printf("\nRunning as a service (see the manual):\n");
                printf("  --install-service   Windows: install the \"BACnetSCHub\" service (start on boot,\n");
                printf("                      restart on failure) running with the --config given here.\n");
                printf("                      Needs an Administrator prompt.\n");
                printf("  --uninstall-service Windows: stop and remove the service.\n");
                printf("                      Linux: use packaging/linux/bacnet-schub-hub.service. SIGTERM\n");
                printf("                      and SIGINT stop the hub cleanly.\n");
                printf("\nConfig file:\n");
                printf("  --config <path>     Read settings from a \"key = value\" file. The settings\n");
                printf("                      above have keys of the same name without \"--\" (--deviceID\n");
                printf("                      is device-id; example.conf lists them all). An option on the\n");
                printf("                      command line still wins over the file. dcc-password and\n");
                printf("                      http-upload-token can ONLY be set in the file, so they\n");
                printf("                      never show in process listings - see docs/manual.md\n");
                printf("                      \"Configuration file\".\n");
                break;
            }
        }
        return 0;
    }
    // --- Config file (Task 2) ------------------------------------------------
    // Loaded BEFORE the individual --port/--deviceID/--sc-*/--dcc-password
    // flags below, precisely so each of those Parse*Arg() calls can be handed
    // the config-file value (if any) as ITS default: those functions already
    // prefer a CLI flag over the default they're given, so this gets CLI args
    // > config file > this example's own built-in defaults "for free", with no
    // separate override pass. See config.h for the file format.
    ExampleConfig fileConfig;
    {
        const std::string configPath = ParseConfigPathArg(argc, argv);
        if (!configPath.empty()) {
            if (!LoadExampleConfig(configPath, &fileConfig)) {
                fprintf(stderr, "Error: could not open --config file \"%s\".\n", configPath.c_str());
                return 1;
            }
        }
    }

    // --- Log file (issue #33) - first, so everything after it is captured ---
    {
        std::string logFile = ParseStringArg(argc, argv, "--log-file");
        if (logFile.empty() && fileConfig.hasLogFile) {
            logFile = fileConfig.logFile;
        }
        if (!logFile.empty()) {
            const uint32_t maxSizeMb = ParseUIntArg(argc, argv, "--log-max-size-mb", 1, 4096,
                fileConfig.hasLogMaxSizeMb ? fileConfig.logMaxSizeMb : 10);
            const uint32_t maxFiles = ParseUIntArg(argc, argv, "--log-max-files", 0, 100,
                fileConfig.hasLogMaxFiles ? fileConfig.logMaxFiles : 5);
            if (LogFile::Start(logFile, (uint64_t)maxSizeMb * 1024 * 1024, maxFiles)) {
                CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                                      "logging to \"%s\" too (rotated at %u MB, %u old file(s) kept)",
                                      logFile.c_str(), maxSizeMb, maxFiles);
            }
        }
    }

    const uint16_t port = CASExampleHelper::ParsePortArg(
        argc, argv, fileConfig.hasPort ? fileConfig.port : 47808);
    {
        const std::string deviceName = ParseStringArg(argc, argv, "--device-name");
        if (!deviceName.empty()) {
            g_deviceName = deviceName;  // CLI wins
        } else if (fileConfig.hasDeviceName) {
            g_deviceName = fileConfig.deviceName;
        }
        g_ipNetworkNumber = (uint16_t)ParseUIntArg(argc, argv, "--ip-network-number", 1, 65534,
            fileConfig.hasIpNetworkNumber ? fileConfig.ipNetworkNumber : 0);
        g_scNetworkNumber = (uint16_t)ParseUIntArg(argc, argv, "--sc-network-number", 1, 65534,
            fileConfig.hasScNetworkNumber ? fileConfig.scNetworkNumber : 0);
    }
    {
        g_bacnetIpEnabled = fileConfig.hasBacnetIp ? fileConfig.bacnetIp : true;
        const std::string bacnetIpArg = ParseStringArg(argc, argv, "--bacnet-ip");
        if (bacnetIpArg == "off" || bacnetIpArg == "false" || bacnetIpArg == "no" || bacnetIpArg == "0") {
            g_bacnetIpEnabled = false;
        } else if (bacnetIpArg == "on" || bacnetIpArg == "true" || bacnetIpArg == "yes" || bacnetIpArg == "1") {
            g_bacnetIpEnabled = true;
        } else if (!bacnetIpArg.empty()) {
            fprintf(stderr, "Error: --bacnet-ip expects on or off, got \"%s\".\n", bacnetIpArg.c_str());
            return 1;
        }
    }
    g_deviceInstance = CASExampleHelper::ParseDeviceIdArg(
        argc, argv, fileConfig.hasDeviceId ? fileConfig.deviceId : g_deviceInstance);
    // dcc-password: CONFIG FILE ONLY (Task 1) - no CLI flag exists for it at
    // all (unlike every other setting here, which is CLI > config file >
    // built-in default). fileConfig.dccPassword's storage lives for the rest
    // of main() (a local, not a temporary), so g_dccPassword pointing into it
    // stays valid for the whole run.
    if (fileConfig.hasDccPassword) {
        g_dccPassword = fileConfig.dccPassword.c_str();
    }
    if (fileConfig.hasHttpUploadToken) {
        g_httpUploadToken = fileConfig.httpUploadToken;  // config file only, like dcc-password
    }
    g_scPort = ParseScPortArg(argc, argv, fileConfig.hasScPort ? fileConfig.scPort : g_scPort);
    g_scCertDir = ParseScCertDirArg(argc, argv, fileConfig.hasScCertDir ? fileConfig.scCertDir : g_scCertDir);

    // --- Lab certificate generation (--generate-certs / --add-client-certs) --
    // A one-shot tool mode: write the certificates, then exit without starting
    // the device. See cert_tool.h.
    {
        unsigned generateCount = 0;
        unsigned addCount = 0;
        bool generateValid = true;
        bool addValid = true;
        const bool generate = ParseOptionalCountArg(argc, argv, "--generate-certs",
            CertTool::DEFAULT_GENERATE_CLIENT_COUNT, &generateCount, &generateValid);
        const bool add = ParseOptionalCountArg(argc, argv, "--add-client-certs",
            CertTool::DEFAULT_ADD_CLIENT_COUNT, &addCount, &addValid);
        if (generate || add) {
            if (!generateValid || !addValid) {
                return 1;
            }
            if (generate && add) {
                fprintf(stderr, "Error: use --generate-certs or --add-client-certs, not both.\n");
                return 1;
            }
            std::string label = ParseStringArg(argc, argv, "--cert-label");
            if (label.empty()) {
                label = CertTool::DEFAULT_CLIENT_LABEL;
            }
            // The hub URI written into each client's bacnetsc.config: this
            // machine's IPv4 address and --sc-port, unless --cert-hub-uri says
            // otherwise (a DNS name, another interface, a NAT address...).
            std::string hubUri = ParseStringArg(argc, argv, "--cert-hub-uri");
            if (hubUri.empty()) {
                uint8_t ip[4] = {127, 0, 0, 1};
                uint8_t mask[4] = {0, 0, 0, 0};
                if (!CASExampleHelper::GetLocalIPv4(ip, mask)) {
                    ip[0] = 127; ip[1] = 0; ip[2] = 0; ip[3] = 1;
                }
                char uri[64];
                snprintf(uri, sizeof(uri), "wss://%u.%u.%u.%u:%u/", ip[0], ip[1], ip[2], ip[3], g_scPort);
                hubUri = uri;
            }
            const bool ok = generate
                ? CertTool::GenerateCertificateSet(g_scCertDir, generateCount, label, hubUri,
                                                   HasFlag(argc, argv, "--force"))
                : CertTool::AddClientCertificates(g_scCertDir, addCount, label, hubUri);
            return ok ? 0 : 1;
        }
    }
    g_scHubUri = ParseStringArg(argc, argv, "--sc-hub-uri");
    if (g_scHubUri.empty() && fileConfig.hasScHubUri) {
        g_scHubUri = fileConfig.scHubUri;
    }
    g_scFailoverUri = ParseStringArg(argc, argv, "--sc-failover-uri");
    if (g_scFailoverUri.empty() && fileConfig.hasScFailoverUri) {
        g_scFailoverUri = fileConfig.scFailoverUri;
    }
    {
        const uint16_t fromFile =
            fileConfig.hasScMaxHubConnections ? fileConfig.scMaxHubConnections : SC_MAX_HUB_CONNECTIONS_DEFAULT;
        g_scMaxHubConnections = ParseScMaxHubConnectionsArg(argc, argv, fromFile);
        const char* source = "the built-in default";
        if (g_scMaxHubConnections != fromFile) {
            source = "the --sc-max-hub-connections command-line option";
        } else if (fileConfig.hasScMaxHubConnections) {
            source = "the config file's sc-max-hub-connections";
        }
        CheckScMaxHubConnectionsLimit(g_scMaxHubConnections, source);
    }
    g_scRateLimit = ParseScRateLimitArg(argc, argv, "--sc-rate-limit",
        fileConfig.hasScRateLimit ? fileConfig.scRateLimit : SC_RATE_LIMIT_DEFAULT);
    g_scRateLimitTotal = ParseScRateLimitArg(argc, argv, "--sc-rate-limit-total",
        fileConfig.hasScRateLimitTotal ? fileConfig.scRateLimitTotal : SC_RATE_LIMIT_TOTAL_DEFAULT);
    g_scAcceptHubWithoutHello = HasFlag(argc, argv, "--sc-accept-hub-without-hello") ||
                                (fileConfig.hasScAcceptHubWithoutHello && fileConfig.scAcceptHubWithoutHello);
    g_httpPort = ParseHttpPortArg(argc, argv, fileConfig.hasHttpPort ? fileConfig.httpPort : g_httpPort);
    {
        const std::string httpBindArg = ParseStringArg(argc, argv, "--http-bind");
        if (!httpBindArg.empty()) {
            g_httpBindAddress = httpBindArg;  // CLI wins
        } else if (fileConfig.hasHttpBind && !fileConfig.httpBind.empty()) {
            g_httpBindAddress = fileConfig.httpBind;  // then config file
        }
        // else: g_httpBindAddress keeps its "127.0.0.1" built-in default.
    }
    g_httpTls = HasFlag(argc, argv, "--http-tls") || (fileConfig.hasHttpTls && fileConfig.httpTls);
    g_httpTlsCert = ParseStringArg(argc, argv, "--http-tls-cert");
    if (g_httpTlsCert.empty() && fileConfig.hasHttpTlsCert) {
        g_httpTlsCert = fileConfig.httpTlsCert;
    }
    g_httpTlsKey = ParseStringArg(argc, argv, "--http-tls-key");
    if (g_httpTlsKey.empty() && fileConfig.hasHttpTlsKey) {
        g_httpTlsKey = fileConfig.httpTlsKey;
    }
    CASExampleHelper::PrintVersion(APP_NAME, APP_VERSION);
    g_startTime = std::chrono::steady_clock::now();

    // Item 5: route libwebsockets' own internal logging through this app's
    // log facility, before ANY lws_context is created (g_scRouter.Start()
    // below binds BACnet/IP only - no lws involved there; the first lws
    // context this process creates is g_scTransport's, further down, or
    // g_httpServer's later still) - see LwsLogCallback's own comment above.
    lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE, &LwsLogCallback);

    // --- Bind the BACnet/IP socket --------------------------------------------
    // Owned by g_scRouter (sc_transport/ScTransportRouter.h), NOT
    // CASExampleHelper::SetupUDP() - the router's own ReceiveMessageForPort/
    // SendMessageForPort callbacks (registered below) must be able to reach
    // this socket directly to dispatch between it and BACnet/SC. The BACnet/IP
    // port stays active regardless of the BACnet/SC transport outcome - see
    // the file header note - unless --bacnet-ip off asked for BACnet/SC only,
    // in which case no socket is opened at all (the router then only ever
    // answers for Network Port 2).
    if (g_bacnetIpEnabled) {
        if (!g_scRouter.Start(port)) {
            return 1;
        }
        g_bacnetIpUdpPort = port;
        if (!CASExampleHelper::GetLocalIPv4(g_ipAddress, g_ipSubnetMask)) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                                  "could not read a local IPv4 address; Network Port IP_Address "
                                  "will report 0.0.0.0.");
        }
    } else {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                              "BACnet/IP is OFF (--bacnet-ip off): no UDP socket, no Network Port 1. "
                              "This device is reachable only over BACnet/SC.");
    }

    // --- Configure the BACnet/SC transport -------------------------------------
    // Build the accept URI from --sc-port now that the CLI has been parsed.
    // "0.0.0.0" = bind every interface (ScTransport::StartListening's contract).
    g_scHubAcceptUri = "wss://0.0.0.0:" + std::to_string(g_scPort) + "/";
    {
        CASSc::ScTlsFiles tls;
        // BACnet-named PEM files from --generate-certs, or the older names
        // from an earlier release - see cert_tool.h.
        const std::string issuer1Path = ScCertFilePath(FILE_ISSUER_CERT_1_INSTANCE);

        // CertStore owns the 4 certificate File objects' contents (section 2d-ii).
        CertStore::Layout layout;
        const uint32_t certInstances[4] = {FILE_OPERATIONAL_CERT_INSTANCE, FILE_CSR_INSTANCE,
                                           FILE_ISSUER_CERT_1_INSTANCE, FILE_ISSUER_CERT_2_INSTANCE};
        for (const uint32_t instance : certInstances) {
            layout.paths[instance] = ScCertFilePath(instance);
        }
        layout.readFallbacks[FILE_ISSUER_CERT_2_INSTANCE] = issuer1Path;
        layout.operationalInstance = FILE_OPERATIONAL_CERT_INSTANCE;
        layout.issuerInstances = {FILE_ISSUER_CERT_1_INSTANCE, FILE_ISSUER_CERT_2_INSTANCE};
        layout.privateKeyPath = g_scCertDir + "/" + CertTool::ResolveCertFile(
            g_scCertDir, CertTool::PRIVATE_KEY_FILE, CertTool::LEGACY_PRIVATE_KEY_FILE);
        CertStore::SetLayout(layout);

        // TLS trusts every issuer in both slots. With no certificates yet, fall
        // back to slot 1's path so the "certificates missing" message names it.
        g_scTrustedIssuersPath = g_scCertDir + "/" + CertTool::TRUSTED_ISSUERS_FILE;
        std::string bundleReason;
        tls.caCertPath = CertStore::WriteTrustedIssuerBundle(g_scTrustedIssuersPath, &bundleReason)
                             ? g_scTrustedIssuersPath : issuer1Path;
        tls.certPath = g_scCertDir + "/" + CertTool::ResolveCertFile(
            g_scCertDir, CertTool::OPERATIONAL_CERTIFICATE_FILE, CertTool::LEGACY_OPERATIONAL_CERTIFICATE_FILE);
        tls.keyPath = g_scCertDir + "/" + CertTool::ResolveCertFile(
            g_scCertDir, CertTool::PRIVATE_KEY_FILE, CertTool::LEGACY_PRIVATE_KEY_FILE);
        // Optional certificate revocation list (issue #15) - see ScTlsFiles::crlPath.
        tls.crlPath = g_scCrlPath = g_scCertDir + "/" + CertTool::ISSUER_CRL_FILE;
        g_scTransport.Configure(tls, "hub.bsc.bacnet.org"); // plan fact 1 - NOT "hub.bacnet.org"
        // Bound how fast the listener accepts new connection attempts, per
        // source address and in total - see g_scRateLimit's comment.
        g_scTransport.SetConnectionRateLimits(g_scRateLimit, g_scRateLimitTotal);
    }

    // --- Register callbacks ---------------------------------------------------
    // RegisterCommonCallbacks() FIRST (it also supplies GetSystemTime), then
    // g_scRouter.RegisterCallbacks() to REPLACE the Receive/SendMessageForPort
    // pointers with the router's own dispatching versions - the stack keeps
    // only ONE pointer per callback slot, so ordering here is load-bearing
    // (see ScTransportRouter.h's class-header comment).
    CASExampleHelper::RegisterCommonCallbacks();
    g_scRouter.RegisterCallbacks();
    BACnetStack_RegisterCallbackGetPropertyReal(GetPropertyReal);
    BACnetStack_RegisterCallbackGetPropertyEnumerated(GetPropertyEnumerated);
    BACnetStack_RegisterCallbackGetPropertyUnsignedInteger(GetPropertyUnsignedInteger);
    BACnetStack_RegisterCallbackGetPropertyCharacterString(GetPropertyCharString);
    BACnetStack_RegisterCallbackGetPropertyBool(GetPropertyBool);
    BACnetStack_RegisterCallbackGetPropertyOctetString(GetPropertyOctetString);
    BACnetStack_RegisterCallbackGetPropertyDate(GetPropertyDate);
    BACnetStack_RegisterCallbackGetPropertyTime(GetPropertyTime);
    // DeviceCommunicationControl (DM-DCC-B).
    BACnetStack_RegisterCallbackDeviceCommunicationControl(DeviceCommunicationControl);
    // BACnet/SC transport callbacks (NM-SCH-B) - both roles are real, see 2c above.
    BACnetStack_RegisterCallbackInitiateWebsocket(CallbackInitiateWebsocket);
    BACnetStack_RegisterCallbackDisconnectWebsocket(CallbackDisconnectWebsocket);
    BACnetStack_RegisterCallbackSCStartListening(CallbackSCStartListening);
    BACnetStack_RegisterCallbackSCStopListening(CallbackSCStopListening);
    BACnetStack_RegisterCallbackBACnetSCStateChange(CallbackBACnetSCStateChange);
    // File objects (phase 4) - AtomicReadFile for the 4 certificate/CSR File
    // objects, see section 2d above.
    BACnetStack_RegisterCallbackReadFile(CallbackReadFile);
    // Certificate writes over BACnet (clause 19.8.3) - see section 2d-ii.
    BACnetStack_RegisterCallbackWriteFile(CallbackWriteFile);
    BACnetStack_RegisterCallbackSetPropertyUnsignedInteger(SetPropertyUnsignedInteger);
    BACnetStack_RegisterCallbackReinitializeDevice(ReinitializeDevice);

    // --- Create the device --------------------------------------------------
    if (!BACnetStack_AddDevice(g_deviceInstance)) {
        printf("Error: Failed to add the Device %u.\n", g_deviceInstance);
        return 1;
    }

    // Enable the services this B-SCHUB profile requires: ReadProperty (DS-RP-B),
    // ReadPropertyMultiple (DS-RPM-B), and DeviceCommunicationControl (DM-DCC-B).
    // WriteProperty, AtomicWriteFile and ReinitializeDevice are enabled further
    // down, only for the BACnet/SC certificate procedures (section 2d-ii). No
    // SubscribeCOV or alarm/event service - a BACnet/SC Hub does not need them.
    if (!BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_READ_PROPERTY, true)) {
        printf("Error: Failed to enable the ReadProperty service.\n");
        return 1;
    }
    // ReadPropertyMultiple (DS-RPM-B) - reuses the SAME per-property Get
    // callbacks already registered above for ReadProperty (confirmed by
    // reading submodules/cas-bacnet-stack/source/BACnetReadPropertyMultipleProcessor.cpp:
    // it resolves each requested property through BACnetBusinessLogic::GetProperty,
    // the identical path BACnetReadPropertyProcessor.cpp uses for single-property
    // ReadProperty). No additional callback registration is needed for RPM.
    if (!BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_READ_PROPERTY_MULTIPLE, true)) {
        printf("Error: Failed to enable the ReadPropertyMultiple service.\n");
        return 1;
    }
    if (!BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_DEVICE_COMMUNICATION_CONTROL, true)) {
        printf("Error: Failed to enable the DeviceCommunicationControl service.\n");
        return 1;
    }
    // AtomicReadFile (phase 4) - required for the 4 certificate/CSR File objects
    // to actually answer reads; see SERVICE_ATOMIC_READ_FILE's own comment above.
    if (!BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_ATOMIC_READ_FILE, true)) {
        printf("Error: Failed to enable the AtomicReadFile service.\n");
        return 1;
    }
    // The BACnet/SC certificate procedures (clause 19.8.3, section 2d-ii):
    // WriteProperty (only a certificate File object's File_Size is writable),
    // AtomicWriteFile (into the operational/issuer certificate File objects) and
    // ReinitializeDevice (ACTIVATE_CHANGES / WARMSTART apply them).
    if (!BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_WRITE_PROPERTY, true) ||
        !BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_ATOMIC_WRITE_FILE, true) ||
        !BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_REINITIALIZE_DEVICE, true)) {
        printf("Error: Failed to enable the certificate-procedure services.\n");
        return 1;
    }

    // Discovery: Who-Is/I-Am (DM-DDB-B) and Who-Has/I-Have (DM-DOB-B). See the
    // B-ASC/B-SA note this pattern is copied from: the stack answers both
    // regardless, but Protocol_Services_Supported is emitted verbatim from
    // these bits, so without them the device would misreport its own support.
    if (!BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_WHO_IS, true) ||
        !BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_I_AM, true) ||
        !BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_WHO_HAS, true) ||
        !BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_I_HAVE, true)) {
        printf("Error: Failed to enable the discovery services (Who-Is/I-Am, Who-Has/I-Have).\n");
        return 1;
    }

    // --- Add the example sensor object ----------------------------------------
    if (!BACnetStack_AddObject(g_deviceInstance, OBJECT_TYPE_ANALOG_INPUT, ANALOG_INPUT_INSTANCE)) {
        printf("Error: Failed to add Analog Input %u (Bronze).\n", ANALOG_INPUT_INSTANCE);
        return 1;
    }

    // --- Add Network Port 1 (BACnet/IP, "BACnet IP") -------------------------
    // Not with --bacnet-ip off: a BACnet/SC-only device has no BACnet/IP port.
    if (g_bacnetIpEnabled && !BACnetStack_AddNetworkPortObject(
            g_deviceInstance, NETWORK_PORT_INSTANCE,
            NETWORK_PORT_NETWORK_TYPE_IPV4,
            NETWORK_PORT_PROTOCOL_LEVEL_BACNET_APPLICATION,
            g_ipNetworkNumber,  // 0 = not configured (--ip-network-number)
            g_ipNetworkNumber != 0 ? NETWORK_NUMBER_QUALITY_CONFIGURED : NETWORK_NUMBER_QUALITY_UNKNOWN,
            NETWORK_PORT_REFERENCE_PORT_NONE)) {
        printf("Error: Failed to add Network Port 1 (BACnet IP).\n");
        return 1;
    }

    // --- Add Network Port 2 (BACnet/SC, "BACnet SC") + configure the hub ---
    // function (NM-SCH-B). The SC protocol/state-machine side is fully real,
    // and (this phase) so is the listener transport (see 2c) - a real SC node
    // can connect to g_scHubAcceptUri once certs exist under --sc-cert-dir.
    if (!BACnetStack_AddNetworkPortObject(
            g_deviceInstance, SC_NETWORK_PORT_INSTANCE,
            NETWORK_PORT_NETWORK_TYPE_SECURE_CONNECT,
            NETWORK_PORT_PROTOCOL_LEVEL_BACNET_APPLICATION,
            g_scNetworkNumber,  // 0 = not configured (--sc-network-number)
            g_scNetworkNumber != 0 ? NETWORK_NUMBER_QUALITY_CONFIGURED : NETWORK_NUMBER_QUALITY_UNKNOWN,
            NETWORK_PORT_REFERENCE_PORT_NONE)) {
        printf("Error: Failed to add Network Port 2 (BACnet SC, BACnet/SC).\n");
        return 1;
    }

    // The device-wide SC UUID. REQUIRED before any SC data link starts, and can
    // only be set once per run (BACnetStack_Reset clears it) - see the doc
    // comment on BACnetStack_SetBACnetSCUuid.
    if (!BACnetStack_SetBACnetSCUuid(SC_DEVICE_UUID, sizeof(SC_DEVICE_UUID))) {
        printf("Error: Failed to set the BACnet/SC device UUID.\n");
        return 1;
    }

    // Configure and enable the hub function on Network Port 2. At least one
    // accept URI is required before enabling (BACnetStack_AddBACnetSCAcceptUri
    // doc comment); connectionRole 0 = hub function.
    if (!BACnetStack_AddBACnetSCAcceptUri(g_deviceInstance, SC_NETWORK_PORT_INSTANCE, 0,
                                          g_scHubAcceptUri.c_str(), (uint32_t)g_scHubAcceptUri.size())) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Error,
                              "cannot start listening: failed to add the BACnet/SC hub accept URI %s.",
                              g_scHubAcceptUri.c_str());
        return 1;
    }
    if (!BACnetStack_SetBACnetSCHubFunctionConfig(g_deviceInstance, SC_NETWORK_PORT_INSTANCE,
                                                  true, g_scMaxHubConnections)) {
        printf("Error: Failed to enable the BACnet/SC hub function.\n");
        return 1;
    }

    // Interoperability relaxation - off by default (see g_scAcceptHubWithoutHello).
    // Device-wide: the stack applies it to every BACnet/SC data link.
    if (g_scAcceptHubWithoutHello) {
        if (!BACnetStack_SetBACnetSCCompatibilityFlags(SC_COMPATIBILITY_ACCEPT_CONNECT_ACCEPT_WITHOUT_HELLO)) {
            printf("Error: Failed to set the BACnet/SC compatibility flags.\n");
            return 1;
        }
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "BACnet/SC compatibility: the hub connector accepts a Connect-Accept without the Hello "
            "option (sc-accept-hub-without-hello). This deviates from ANSI/ASHRAE 135 AB.2.2.");
    }

    // --- Add the 4 certificate/CSR File objects (phase 4) -------------------
    // and bind them to Network Port 2's SC certificate properties. Content is
    // served from --sc-cert-dir by CallbackReadFile (section 2d) - never the
    // private key. The operational and issuer certificates are writable for the
    // clause 19.8.3 certificate procedures (section 2d-ii); the Certificate
    // Signing Request is read-only.
    if (!BACnetStack_AddFileObject(g_deviceInstance, FILE_OPERATIONAL_CERT_INSTANCE,
                                   /*isWritable*/ true, /*isConfigurationFile*/ false,
                                   FILE_ACCESS_METHOD_STREAM)) {
        printf("Error: Failed to add File %u (Operational Certificate, operational certificate).\n", FILE_OPERATIONAL_CERT_INSTANCE);
        return 1;
    }
    if (!BACnetStack_AddFileObject(g_deviceInstance, FILE_CSR_INSTANCE,
                                   /*isWritable*/ false, /*isConfigurationFile*/ false,
                                   FILE_ACCESS_METHOD_STREAM)) {
        printf("Error: Failed to add File %u (CSR, certificate signing request).\n", FILE_CSR_INSTANCE);
        return 1;
    }
    if (!BACnetStack_AddFileObject(g_deviceInstance, FILE_ISSUER_CERT_1_INSTANCE,
                                   /*isWritable*/ true, /*isConfigurationFile*/ false,
                                   FILE_ACCESS_METHOD_STREAM)) {
        printf("Error: Failed to add File %u (Issuer Certificate Slot 1, issuer certificate 1).\n", FILE_ISSUER_CERT_1_INSTANCE);
        return 1;
    }
    if (!BACnetStack_AddFileObject(g_deviceInstance, FILE_ISSUER_CERT_2_INSTANCE,
                                   /*isWritable*/ true, /*isConfigurationFile*/ false,
                                   FILE_ACCESS_METHOD_STREAM)) {
        printf("Error: Failed to add File %u (Issuer Certificate Slot 2, issuer certificate 2).\n", FILE_ISSUER_CERT_2_INSTANCE);
        return 1;
    }
    {
        // Exactly 2 issuer slots - the stack requires this regardless of how many
        // distinct CAs are in use. Slot 2 serves slot 1's certificate until a
        // client writes its own (see ScCertFileRelativePath).
        const uint32_t issuerCertificateFileInstances[2] = {
            FILE_ISSUER_CERT_1_INSTANCE, FILE_ISSUER_CERT_2_INSTANCE
        };
        if (!BACnetStack_SetBACnetSCCertificateFileObjects(
                g_deviceInstance, SC_NETWORK_PORT_INSTANCE,
                /*hasOperationalCertificateFile*/ true, FILE_OPERATIONAL_CERT_INSTANCE,
                /*hasCertificateSigningRequestFile*/ true, FILE_CSR_INSTANCE,
                issuerCertificateFileInstances, 2)) {
            printf("Error: Failed to bind Network Port %u's SC certificate File objects.\n", SC_NETWORK_PORT_INSTANCE);
            return 1;
        }
    }

    // --- Optionally ALSO configure the hub CONNECTOR (initiator) role -------
    // Off unless --sc-hub-uri was given (see g_scHubUri's own comment) - the
    // stack rejects an empty primary URI, and this hub-only example does not
    // need a connector to answer a node's own requests (plan open risk #8).
    if (!g_scHubUri.empty()) {
        // CORRECTION (found reviewing why Network Port 2's MAC_Address (423)
        // reads all-zero in the default hub-function-only run): an earlier
        // version of this comment claimed the hub-function role "derives its
        // own [VMAC] internally." That is wrong - verified by reading
        // submodules/cas-bacnet-stack/source/BACnetDataLinkSC_NetworkPort.cpp's
        // SyncTrackedBACnetSCNetworkPort(): Network Port MAC_Address is set
        // from BACnetSCHubConnector::GetVmac() ONLY when a hub connector
        // exists (hubConnector != NULL) - i.e. only when THIS function's own
        // BACnetStack_SetBACnetSCHubConnectorForNetworkPort call has actually
        // run at least once. When it hasn't (the default: hub-function-only,
        // no --sc-hub-uri), the same sync function explicitly resets
        // MAC_Address to empty every cycle (SetSCMACAddress(NULL, 0)) - there
        // is no separate "hub function's own VMAC" anywhere in the adapter's
        // public API (grepped CASBACnetStackAdapterTypes.h for every
        // SetNetworkPortSC*/SetBACnetSC* entry point). So an all-zero
        // MAC_Address on Network Port 2 in this example's default
        // configuration is the stack's own intended behaviour, not a bug -
        // it only ever gets populated by THIS branch running, which computes
        // its own vmac below the same way BACnetStack_SetBACnetSCUuid's own
        // doc comment describes ("the last 6 octets of the UUID, XORing the
        // final octet with 0x01 if those 6 octets would otherwise be
        // all-zero or all-FF") because this is the SAME device/UUID dialing
        // out under the SAME identity, not a separate one -
        // BACnetStack_SetBACnetSCHubConnectorForNetworkPort takes the VMAC
        // explicitly, so this example must compute it itself.
        uint8_t vmac[6];
        memcpy(vmac, SC_DEVICE_UUID + (sizeof(SC_DEVICE_UUID) - 6), 6);
        bool allZero = true, allFF = true;
        for (int i = 0; i < 6; ++i) {
            if (vmac[i] != 0x00) allZero = false;
            if (vmac[i] != 0xFF) allFF = false;
        }
        if (allZero || allFF) {
            vmac[5] ^= 0x01;
        }

        if (!BACnetStack_SetBACnetSCHubConnectorForNetworkPort(
                g_deviceInstance, SC_NETWORK_PORT_INSTANCE, vmac, sizeof(vmac),
                g_scHubUri.c_str(), (uint16_t)g_scHubUri.size(),
                g_scFailoverUri.c_str(), (uint16_t)g_scFailoverUri.size())) {
            printf("Error: Failed to configure the BACnet/SC hub connector (--sc-hub-uri \"%s\").\n",
                   g_scHubUri.c_str());
            return 1;
        }
        printf("FYI: BACnet/SC hub CONNECTOR is CONFIGURED on Network Port %u, dialing primary hub %s%s%s.\n",
               SC_NETWORK_PORT_INSTANCE, g_scHubUri.c_str(),
               g_scFailoverUri.empty() ? "" : " (failover ", g_scFailoverUri.empty() ? "" : (g_scFailoverUri + ")").c_str());
    }

    // --- Enable the OPTIONAL properties we choose to expose ------------------
    // Description on every object (served by GetPropertyCharString from
    // ObjectDescription()). An optional property needs SetPropertyEnabled, not
    // just a callback branch: the stack checks it before calling the callback.
    {
        struct { uint16_t type; uint32_t instance; } objects[] = {
            {OBJECT_TYPE_DEVICE, g_deviceInstance},
            {OBJECT_TYPE_ANALOG_INPUT, ANALOG_INPUT_INSTANCE},
            {OBJECT_TYPE_NETWORK_PORT, NETWORK_PORT_INSTANCE},
            {OBJECT_TYPE_NETWORK_PORT, SC_NETWORK_PORT_INSTANCE},
            {OBJECT_TYPE_FILE, FILE_OPERATIONAL_CERT_INSTANCE},
            {OBJECT_TYPE_FILE, FILE_CSR_INSTANCE},
            {OBJECT_TYPE_FILE, FILE_ISSUER_CERT_1_INSTANCE},
            {OBJECT_TYPE_FILE, FILE_ISSUER_CERT_2_INSTANCE},
        };
        for (const auto& o : objects) {
            if (o.type == OBJECT_TYPE_NETWORK_PORT && o.instance == NETWORK_PORT_INSTANCE && !g_bacnetIpEnabled) {
                continue;  // Network Port 1 doesn't exist in BACnet/SC-only mode
            }
            if (!BACnetStack_SetPropertyEnabled(g_deviceInstance, o.type, o.instance,
                                                PROPERTY_IDENTIFIER_DESCRIPTION, true)) {
                printf("Error: Failed to enable Description on object type %u instance %u.\n",
                       (unsigned)o.type, o.instance);
                return 1;
            }
        }
    }

    // Who-Is is answered automatically. The spec also requires a device to
    // announce itself on start-up, so broadcast an unsolicited I-Am now (to the
    // local subnet broadcast - the BACnet/IP Network Port's own network).
    // g_scRouter.SendIAm(), not CASExampleHelper::SendIAm() - the router owns
    // Network Port 1's UDP socket directly (see the "Bind the BACnet/IP
    // socket" comment above). With BACnet/IP off there is no one to tell yet:
    // no BACnet/SC device is connected at start-up, and each one that
    // connects discovers this device with Who-Is.
    if (g_bacnetIpEnabled) {
        g_scRouter.SendIAm(g_deviceInstance);
    }

    printf("FYI: Device %u (\"%s\") ready. Vendor ID %u. Press 'h' for help, 'm' for a health/metrics snapshot.\n",
           g_deviceInstance, g_deviceName.c_str(), VENDOR_IDENTIFIER);
    printf("FYI: BACnet/SC hub function is CONFIGURED on Network Port %u "
           "(BACnet SC), accept URI %s. Certificates: %s. See docs/manual.md "
           "\"BACnet/SC support\" for how to generate lab test certs.\n",
           SC_NETWORK_PORT_INSTANCE, g_scHubAcceptUri.c_str(), g_scCertDir.c_str());

    // --- Start the HTTP health/metrics + certificate-upload endpoint --------
    // (Tasks 3/4). Not fatal if this fails to bind (see HttpServer::Start's
    // own comment) - BACnet/IP and BACnet/SC keep running regardless.
    {
        CASSc::HttpServerConfig httpConfig;
        httpConfig.port = g_httpPort;
        httpConfig.bindAddress = g_httpBindAddress;
        httpConfig.certDir = g_scCertDir;
        if (g_httpTls) {
            // HTTPS (issue #22): the named certificate/key, or the hub's own.
            httpConfig.tlsCertPath = !g_httpTlsCert.empty() ? g_httpTlsCert : g_scCertDir + "/" +
                CertTool::ResolveCertFile(g_scCertDir, CertTool::OPERATIONAL_CERTIFICATE_FILE,
                                          CertTool::LEGACY_OPERATIONAL_CERTIFICATE_FILE);
            httpConfig.tlsKeyPath = !g_httpTlsKey.empty() ? g_httpTlsKey : g_scCertDir + "/" +
                CertTool::ResolveCertFile(g_scCertDir, CertTool::PRIVATE_KEY_FILE,
                                          CertTool::LEGACY_PRIVATE_KEY_FILE);
        }
        httpConfig.bearerToken = g_httpUploadToken;  // empty => upload endpoint disabled entirely
        httpConfig.resolveCertSlot = ResolveCertUploadSlot;
        httpConfig.applyCertUpload = ApplyCertUpload;  // validated like a BACnet write - issue #25
        httpConfig.buildHealthJson = BuildHealthJson;
        httpConfig.buildMetricsJson = BuildMetricsJson;
        httpConfig.buildStatusPage = BuildStatusPage;  // GET / - see BuildStatusPage()
        g_httpServer.Start(httpConfig);
    }

    // --- Run the stack ------------------------------------------------------
    std::string crlFingerprint = FileFingerprint(g_scCrlPath);
    std::chrono::steady_clock::time_point lastCrlCheck = std::chrono::steady_clock::now();
    bool checkedScOnlyReachable = false;  // the --bacnet-ip off warning, once (issue #35)
    bool running = true;
    while (running && !Service::StopRequested()) {  // SIGTERM/SIGINT or a service stop ends the loop
        BACnetStack_Tick();

        // Pump the WebSocket/TLS transport non-blockingly, then report any
        // resulting connection-status changes to the stack. NEVER call
        // BACnetStack_* from inside an lws callback (plan fact 6) - Service()
        // only queues; DrainStatusEvents() is what actually calls
        // BACnetStack_SetBACnetSCWebSocketStatus, safely here in the main loop.
        g_scTransport.Service();
        g_scRouter.DrainStatusEvents();

        // BACnet/SC-only and BACnet/SC not listening = unreachable over BACnet
        // (issue #35). Checked once, a few seconds in: the stack starts the
        // listener on its first Ticks, not during configuration. It keeps
        // retrying after that, and /health reports degraded.
        if (!g_bacnetIpEnabled && !checkedScOnlyReachable &&
            std::chrono::steady_clock::now() - g_startTime >= std::chrono::seconds(3)) {
            checkedScOnlyReachable = true;
            if (!g_scTransport.IsListening()) {
                CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                    "BACnet/IP is off and BACnet/SC is NOT listening (see the certificate messages above) - "
                    "this device is UNREACHABLE over BACnet until BACnet/SC starts. Fix the certificates in "
                    "\"%s\" (it retries every 5 s), or run with --bacnet-ip on.", g_scCertDir.c_str());
            }
        }

        // A new, changed or removed certificate revocation list (issue #15):
        // reload TLS so it is used. Restarting the listener drops every
        // device; each reconnects, and one whose certificate is now revoked
        // is refused - which is how an open connection from a revoked device
        // is closed.
        if (std::chrono::steady_clock::now() - lastCrlCheck >= std::chrono::seconds(5)) {
            lastCrlCheck = std::chrono::steady_clock::now();
            const std::string fingerprint = FileFingerprint(g_scCrlPath);
            if (fingerprint != crlFingerprint) {
                crlFingerprint = fingerprint;
                CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                    "SC revocation: \"%s\" %s - reloading BACnet/SC TLS; devices reconnect, revoked ones are refused",
                    g_scCrlPath.c_str(), fingerprint.empty() ? "removed" : "changed");
                g_scReloadCredentialsRequested = true;
            }
        }

        // New certificates activated by ReinitializeDevice (section 2d-ii), an
        // HTTP upload, or a CRL change: rebuild the TLS contexts so they load
        // the new files (the trusted-issuer bundle is already refreshed). The
        // stack restarts the SC port by itself only when a File object
        // REFERENCE changed, not the contents, so this is what applies a
        // content-only change. Peers reconnect under the new certificates.
        if (g_scReloadCredentialsRequested) {
            g_scReloadCredentialsRequested = false;
            g_scTransport.ReloadCredentials();
        }
        g_httpServer.Service(); // Tasks 3/4 - non-blocking, same mechanism as g_scTransport.Service()

        // No console keys when running as a Windows service (there is no console).
        switch (Service::IsService() ? CASExampleHelper::KeyCommand::None : CASExampleHelper::PollKey()) {
            case CASExampleHelper::KeyCommand::Help:
                CASExampleHelper::PrintHelp(APP_NAME, APP_VERSION);
                break;
            case CASExampleHelper::KeyCommand::Quit:
                running = false;
                break;
            case CASExampleHelper::KeyCommand::ArrowUp:
                g_analogInput1Value += 1.1f;
                printf("Analog Input 1 (Bronze) = %.1f C\n", g_analogInput1Value);
                break;
            case CASExampleHelper::KeyCommand::ArrowDown:
                g_analogInput1Value -= 1.1f;
                printf("Analog Input 1 (Bronze) = %.1f C\n", g_analogInput1Value);
                break;
            case CASExampleHelper::KeyCommand::Metrics:
                PrintHealthSnapshot();
                break;
            case CASExampleHelper::KeyCommand::None:
            default:
                break;
        }

#if defined(_WIN32)
        Sleep(1); // 1 ms - be a good citizen, don't spin the CPU
#else
        usleep(1000);
#endif
    }

    CASExampleHelper::RestoreInput();
    g_httpServer.Stop();
    g_scRouter.Shutdown();
    printf("FYI: stopped.\n");
    LogFile::Stop();
    return 0;
}

int main(int argc, char** argv) {
    int exitCode = 0;
    if (Service::HandleServiceCommand(argc, argv, &exitCode)) {  // --install-service / --uninstall-service
        return exitCode;
    }
    return Service::Run(argc, argv, RunHub);
}
