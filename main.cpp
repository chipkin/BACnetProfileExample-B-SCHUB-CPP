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
//     Binary Input  1               "Emerald"                   (active / inactive; read-only)
//     Multi-State Input 1           "Hot Pink"                  (state 1..3; read-only)
//     Network Port 1                "BACnet IP"                 (the BACnet/IP port - required, kept
//                                                                 active so the device stays
//                                                                 discoverable over plain BACnet/IP)
//     Network Port 2                "BACnet SC"                 (the BACnet/SC port - hub function)
//     File 1                        "Operational Certificate"   (read-only; serves the hub's operational
//                                                                 certificate, certs/hub.crt)
//     File 2                        "CSR"                       (read-only; serves the hub's CSR, certs/hub.csr)
//     File 3                        "Issuer Certificate Slot 1" (read-only; issuer certificate slot 1,
//                                                                 certs/ca.crt)
//     File 4                        "Issuer Certificate Slot 2" (read-only; issuer certificate slot 2, also
//                                                                 certs/ca.crt - the stack requires exactly 2
//                                                                 issuer slots; this lab setup has one CA, so
//                                                                 both slots point at it)
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
// This device's certificate policy is CA-chain validation only, performed by
// the TLS library (OpenSSL, via libwebsockets) at handshake time: no CRL, no
// UUID-in-SAN binding, and the connector skips hostname checking
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
static const char* APP_VERSION = "1.1.15";

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
// whole BACnet internetwork, and here it is a COMPILE-TIME constant. The device
// instance is runtime-configurable via --deviceID, so it is easy to ship two
// units, configure their instances correctly, and still have BOTH announce
// Object_Name "Chipkin Example B-SCHUB" - a spec violation, and a hard BTL failure. In a real
// product Object_Name must be per-unit configurable too: derive it from a serial
// number, DIP switches, a config file, or add a --deviceName argument.
static const char* DEVICE_NAME = "Chipkin Example B-SCHUB";

// The Device object's Description. Change it to what YOUR device actually is;
// this string describes this tutorial.
static const char* DEVICE_DESCRIPTION =
    "Chipkin CAS BACnet Stack example - B-SCHUB (BACnet/SC Hub) profile. "
    "Demonstrates DS-RP-B + DM-DDB-B + DM-DOB-B + DM-DCC-B + NM-SCH-B: "
    "ReadProperty, discovery, DeviceCommunicationControl and a real BACnet/SC "
    "hub function (mutual-TLS WebSocket transport, both listener and connector "
    "roles) Network Port, alongside an always-active BACnet/IP port. See "
    "README.md and TUTORIAL.md.";

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
// calling it for that purpose - see README.md "Secrets handling" for why a
// CLI argument is a real exposure a config-file key is not: it is visible in
// process listings/shell history on every platform). Not a compile-time
// constant, so it is NOT `static const` like the rest of this identity block;
// see main()'s config-file-loading block, which points this at
// fileConfig.dccPassword's storage (a local that lives for the rest of
// main()) when the key is present. This same value doubles as the bearer
// token POST /certs/<slot> (Task 4) requires - see g_httpServer's Configure
// call below.
static const char* g_dccPassword = "";  // default: "" = no password required

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
static const uint32_t BINARY_INPUT_INSTANCE = 1;       // "Emerald"
static const uint32_t MULTI_STATE_INPUT_INSTANCE = 1;  // "Hot Pink"
static const uint32_t MULTI_STATE_INPUT_NUMBER_OF_STATES = 3;

// Network Port 1 - the BACnet/IP port every BACnet device must have. Kept
// active so this example stays discoverable over plain BACnet/IP regardless of
// the BACnet/SC transport outcome (see the file header note above).
static const uint32_t NETWORK_PORT_INSTANCE = 1;       // "BACnet IP"
static const uint32_t MAX_APDU_LENGTH = 1476;          // BACnet/IP APDU length

// Network Port 2 - the BACnet/SC port, hosting the hub function (NM-SCH-B).
// BACnetNetworkType::secureConnect = 11 (source/BACnetNetworkType.h). This is a
// LOCAL constant, not added to common/CASBACnetStackExampleConstants.h - that
// file is the series-wide vendored common/ helper (owned by B-SS-CPP; changing
// it is a separate, serialised protocol - see the series runbook §1). A single
// example needing one extra constant does not justify a common/ change.
static const uint8_t NETWORK_PORT_NETWORK_TYPE_SECURE_CONNECT = 11;
static const uint32_t SC_NETWORK_PORT_INSTANCE = 2;     // "BACnet SC"

// The hub function's max simultaneous inbound peer connections - the built-in
// default (used when neither --sc-max-hub-connections nor a config-file
// sc-max-hub-connections key is given). Runtime-configurable as of Task 3
// (previously a hardcoded constant used directly below); see g_scMaxHubConnections
// and ParseScMaxHubConnectionsArg() below. Enforced by the STACK, not this
// example: BACnetSCHubFunctionManager.cpp rejects a Connect-Request once
// m_hubFunctionAcceptedConnections.size() >= maxConnections
// (HubFunctionPeerUpsertResult_TableFull) - a real BACnet/SC-protocol-level
// rejection, not merely advisory and not a raw-socket/TCP-level limit (the
// WebSocket/TLS handshake in sc_transport/ScTransport still completes; the
// stack rejects at the BVLC-SC Connect-Request step that follows).
static const uint16_t SC_MAX_HUB_CONNECTIONS_DEFAULT = 4;

// The runtime value actually passed to BACnetStack_SetBACnetSCHubFunctionConfig -
// see main()'s CLI-parsing block (--sc-max-hub-connections / config-file
// sc-max-hub-connections; CLI > config file > SC_MAX_HUB_CONNECTIONS_DEFAULT).
static uint16_t g_scMaxHubConnections = SC_MAX_HUB_CONNECTIONS_DEFAULT;

// The hub function's max NEW inbound connection ATTEMPTS/second (this batch's
// Task 2) - distinct from SC_MAX_HUB_CONNECTIONS_DEFAULT above, which bounds
// CONCURRENT connections at the BACnet/SC protocol level. This one bounds
// how fast an attacker (or a misbehaving/flapping peer) can make the hub
// spend raw-socket/TLS resources, enforced by
// sc_transport/ScTransport::AllowNewConnectionAttempt() at
// LWS_CALLBACK_FILTER_NETWORK_CONNECTION - before the TLS handshake even
// starts (see that method's comment). 10/sec is a generous default: a real
// reconnect storm from this example's own handful of demo peers is nowhere
// near this rate (BACnetSCCli.exe's own reconnect backoff is on the order of
// seconds, not sub-100ms), so this default only bites under an actual flood,
// never normal reconnect churn. Runtime-configurable the same way as
// SC_MAX_HUB_CONNECTIONS_DEFAULT above - see g_scRateLimit and
// ParseScRateLimitArg() below.
static const uint16_t SC_RATE_LIMIT_DEFAULT = 10;

// The runtime value actually passed to
// ScTransport::SetMaxConnectionAttemptsPerSecond() - see main()'s
// CLI-parsing block (--sc-rate-limit / config-file sc-rate-limit; CLI >
// config file > SC_RATE_LIMIT_DEFAULT). 0 means "no limit".
static uint16_t g_scRateLimit = SC_RATE_LIMIT_DEFAULT;

// The 4 read-only File objects Network Port 2's SC certificate properties point at - see
// BACnetStack_SetBACnetSCCertificateFileObjects's call in main() and RegisterCallbackReadFile
// in section 2d. Same "local constant, not common/" rationale as
// NETWORK_PORT_NETWORK_TYPE_SECURE_CONNECT above: File is a series-wide object type, but no
// other example in the series has needed one yet, so there is nothing to share in common/.
// Named for what each one is (Operational Certificate / CSR / Issuer Certificate Slot 1-2)
// rather than a colour, deliberately breaking from this series' usual naming convention - see
// the file header note above for why.
static const uint32_t FILE_OPERATIONAL_CERT_INSTANCE = 1;  // "Operational Certificate"   - certs/hub.crt
static const uint32_t FILE_CSR_INSTANCE = 2;                // "CSR" - certs/hub.csr
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

// Returns the filename (relative to g_scCertDir) for one of the 4 File object
// instances above, or NULL if fileInstance isn't one of them.
static const char* ScCertFileRelativePath(const uint32_t fileInstance) {
    switch (fileInstance) {
        case FILE_OPERATIONAL_CERT_INSTANCE: return "hub.crt";
        case FILE_CSR_INSTANCE:               return "hub.csr";
        case FILE_ISSUER_CERT_1_INSTANCE:     return "ca.crt";
        case FILE_ISSUER_CERT_2_INSTANCE:     return "ca.crt"; // same CA both slots - see the
                                                                // instance's own comment above
        default: return NULL;
    }
}

// Full on-disk path for a File object instance, or "" if it isn't one of the 4.
static std::string ScCertFilePath(const uint32_t fileInstance) {
    const char* relative = ScCertFileRelativePath(fileInstance);
    if (relative == NULL) {
        return std::string();
    }
    return g_scCertDir + "/" + relative;
}

// Stats the file for a File object instance. Returns false (leaving *size/*mtime
// untouched) if it isn't one of the 4 File objects or the file can't be stat'd
// (e.g. --sc-cert-dir doesn't have it yet - same "certs missing" case ScTransport
// already handles for the listener).
static bool StatScCertFile(const uint32_t fileInstance, long* size, time_t* mtime) {
    const std::string path = ScCertFilePath(fileInstance);
    if (path.empty()) {
        return false;
    }
#if defined(_WIN32)
    struct _stat st;
    if (_stat(path.c_str(), &st) != 0) {
        return false;
    }
#else
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
#endif
    *size = (long)st.st_size;
    *mtime = st.st_mtime;
    return true;
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

// ENUMERATED - the Binary Input's Present_Value (0 = inactive, 1 = active) and
// the Analog Input's Units (degrees Celsius).
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
    if (objectType == OBJECT_TYPE_BINARY_INPUT &&
        objectInstance == BINARY_INPUT_INSTANCE) {
        if (propertyIdentifier == PROPERTY_IDENTIFIER_PRESENT_VALUE) {
            // ON REAL HARDWARE: return your cached input state here - the same rule
            // as GetPropertyReal above applies (never block this callback on slow
            // I/O; sample on a timer/another thread and hand back the latest).
            *value = 0; // inactive - the series-wide starting value
            return true;
        }
        if (propertyIdentifier == PROPERTY_IDENTIFIER_POLARITY) {
            *value = POLARITY_NORMAL; // required property of a Binary Input
            return true;
        }
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

// UNSIGNED INTEGER - the Multi-State Input's Present_Value, and the Device's
// Vendor_Identifier (the stack also uses Vendor_Identifier to build I-Am).
bool GetPropertyUnsignedInteger(const uint32_t deviceInstance, const uint16_t objectType,
                                const uint32_t objectInstance, const uint32_t propertyIdentifier,
                                uint32_t* value, const bool useArrayIndex,
                                const uint32_t propertyArrayIndex, uint32_t* errorCode) {
    (void)errorCode;
    if (deviceInstance != g_deviceInstance) {
        return false;
    }
    if (objectType == OBJECT_TYPE_MULTI_STATE_INPUT &&
        objectInstance == MULTI_STATE_INPUT_INSTANCE) {
        if (propertyIdentifier == PROPERTY_IDENTIFIER_PRESENT_VALUE) {
            *value = 1; // state 1 (valid range is 1..Number_Of_States)
            return true;
        }
        if (propertyIdentifier == PROPERTY_IDENTIFIER_NUMBER_OF_STATES) {
            *value = MULTI_STATE_INPUT_NUMBER_OF_STATES; // required property
            return true;
        }
        // State_Text is an array. The stack asks for its LENGTH here (array
        // index 0) before reading each element via GetPropertyCharString.
        if (propertyIdentifier == PROPERTY_IDENTIFIER_STATE_TEXT &&
            useArrayIndex && propertyArrayIndex == 0) {
            *value = MULTI_STATE_INPUT_NUMBER_OF_STATES;
            return true;
        }
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
         objectType == OBJECT_TYPE_BINARY_INPUT ||
         objectType == OBJECT_TYPE_MULTI_STATE_INPUT ||
         objectType == OBJECT_TYPE_NETWORK_PORT)) {
        *value = false;
        return true;
    }
    // Archive / Read_Only (both required; no stack default) - all 4 File objects
    // are plain, never-archived, read-only certificate/CSR files. Read_Only mirrors
    // the isWritable=false given to BACnetStack_AddFileObject; Archive is served
    // here because it has no stack default either, even though nothing ever writes
    // it (this device does not implement WriteProperty - see the file header).
    if (objectType == OBJECT_TYPE_FILE && ScCertFileRelativePath(objectInstance) != NULL) {
        if (propertyIdentifier == PROPERTY_IDENTIFIER_ARCHIVE) {
            *value = false;
            return true;
        }
        if (propertyIdentifier == PROPERTY_IDENTIFIER_READ_ONLY) {
            *value = true;
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

    // State_Text (optional) - one label per state of the Multi-State Input. It is
    // a BACnet array, so the stack asks for one element at a time by index
    // (1..Number_Of_States). Present_Value 1 -> "On", 2 -> "Off", 3 -> "Auto".
    if (objectType == OBJECT_TYPE_MULTI_STATE_INPUT &&
        objectInstance == MULTI_STATE_INPUT_INSTANCE &&
        propertyIdentifier == PROPERTY_IDENTIFIER_STATE_TEXT && useArrayIndex) {
        static const char* const stateText[] = { "On", "Off", "Auto" };
        if (propertyArrayIndex >= 1 && propertyArrayIndex <= MULTI_STATE_INPUT_NUMBER_OF_STATES) {
            return ReturnCharacterString(stateText[propertyArrayIndex - 1], value,
                                         valueElementCount, maxElementCount, encodingType);
        }
        *errorCode = ERROR_CODE_INVALID_ARRAY_INDEX;
        return false;
    }

    // Object_Name - a colour name for the Device/sensor objects (this series'
    // convention); a purpose name for the Network Ports and File objects
    // (deliberately not a colour - see the file header note).
    if (propertyIdentifier == PROPERTY_IDENTIFIER_OBJECT_NAME) {
        if (objectType == OBJECT_TYPE_DEVICE && objectInstance == g_deviceInstance) {
            return ReturnCharacterString(DEVICE_NAME, value, valueElementCount, maxElementCount, encodingType);
        }
        if (objectType == OBJECT_TYPE_ANALOG_INPUT && objectInstance == ANALOG_INPUT_INSTANCE) {
            return ReturnCharacterString("Bronze", value, valueElementCount, maxElementCount, encodingType);
        }
        if (objectType == OBJECT_TYPE_BINARY_INPUT && objectInstance == BINARY_INPUT_INSTANCE) {
            return ReturnCharacterString("Emerald", value, valueElementCount, maxElementCount, encodingType);
        }
        if (objectType == OBJECT_TYPE_MULTI_STATE_INPUT && objectInstance == MULTI_STATE_INPUT_INSTANCE) {
            return ReturnCharacterString("Hot Pink", value, valueElementCount, maxElementCount, encodingType);
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
                case FILE_CSR_INSTANCE:               return ReturnCharacterString("CSR", value, valueElementCount, maxElementCount, encodingType);
                case FILE_ISSUER_CERT_1_INSTANCE:     return ReturnCharacterString("Issuer Certificate Slot 1", value, valueElementCount, maxElementCount, encodingType);
                case FILE_ISSUER_CERT_2_INSTANCE:     return ReturnCharacterString("Issuer Certificate Slot 2", value, valueElementCount, maxElementCount, encodingType);
                default: break;
            }
        }
    }

    // File_Type (required; no stack default - property-profile-reference.md's File
    // section) - all 4 File objects hold PEM text (certificates/CSR), never the key.
    if (propertyIdentifier == PROPERTY_IDENTIFIER_FILE_TYPE && objectType == OBJECT_TYPE_FILE &&
        ScCertFileRelativePath(objectInstance) != NULL) {
        return ReturnCharacterString("application/x-pem-file", value, valueElementCount, maxElementCount, encodingType);
    }

    // The remaining strings are all on the Device object - its identity, read
    // by clients and used to populate the device's I-Am / object list.
    if (objectType == OBJECT_TYPE_DEVICE && objectInstance == g_deviceInstance) {
        switch (propertyIdentifier) {
            case PROPERTY_IDENTIFIER_DESCRIPTION:
                return ReturnCharacterString(DEVICE_DESCRIPTION, value, valueElementCount, maxElementCount, encodingType);
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
bool DeviceCommunicationControl(const uint32_t deviceInstance, const uint8_t enableDisable,
                                const char* password, const uint8_t passwordLength,
                                const bool useTimeDuration, const uint16_t timeDuration,
                                uint32_t* errorCode) {
    if (deviceInstance != g_deviceInstance) {
        *errorCode = ERROR_CODE_OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED;
        return false;
    }

    const size_t requiredLength = strlen(g_dccPassword);
    if (requiredLength > 0) {
        bool matches = (password != NULL) && (passwordLength == requiredLength);
        if (matches) {
            for (size_t i = 0; i < requiredLength; ++i) {
                if (password[i] != g_dccPassword[i]) {
                    matches = false;
                    break;
                }
            }
        }
        if (!matches) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                                  "DeviceCommunicationControl: REJECTED (password failure)");
            *errorCode = ERROR_CODE_PASSWORD_FAILURE;
            return false;
        }
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
    const std::string path = ScCertFilePath(fileInstance);
    if (path.empty()) {
        return false;
    }
    FILE* f = fopen(path.c_str(), "rb");
    if (f == NULL) {
        // Cert file missing under --sc-cert-dir (same condition ScTransport's
        // listener already handles for the TLS side) - Abort(other) rather than a
        // fabricated empty file, so a client sees this failed rather than believing
        // it read a real, empty certificate.
        return false;
    }
    fseek(f, 0, SEEK_END);
    const long totalSize = ftell(f);
    if (totalSize < 0 || (uint32_t)totalSize < fileStart) {
        fclose(f);
        return false; // fileStart past end-of-file
    }
    fseek(f, (long)fileStart, SEEK_SET);
    uint32_t remaining = (uint32_t)totalSize - fileStart;
    uint32_t toRead = requestedCount < remaining ? requestedCount : remaining;
    if (toRead > maxFileDataLength) {
        toRead = maxFileDataLength; // stream reads are silently clamped, per this
                                     // callback's own doc comment - never abort here
    }
    const size_t bytesRead = toRead > 0 ? fread(fileData, 1, toRead, f) : 0;
    fclose(f);
    *fileDataLength = (uint32_t)bytesRead;
    *endOfFile = (fileStart + bytesRead) >= (uint32_t)totalSize;
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

// Maps a cert-upload slot name (POST /certs/<slot>) to the relative filename
// under --sc-cert-dir it overwrites - the SAME mapping ScCertFileRelativePath
// (2a-i) already uses for the read-only File objects, just addressed by a
// short slot name instead of a File object instance (an HTTP client has no
// reason to know this device's internal object-instance numbering). Returns
// false for an unrecognised slot.
static bool ResolveCertUploadSlot(const std::string& slot, std::string* outRelativeFilename) {
    uint32_t fileInstance;
    if (slot == "operational") {
        fileInstance = FILE_OPERATIONAL_CERT_INSTANCE;
    } else if (slot == "csr") {
        fileInstance = FILE_CSR_INSTANCE;
    } else if (slot == "issuer1") {
        fileInstance = FILE_ISSUER_CERT_1_INSTANCE;
    } else if (slot == "issuer2") {
        fileInstance = FILE_ISSUER_CERT_2_INSTANCE;
    } else {
        return false;
    }
    const char* relative = ScCertFileRelativePath(fileInstance);
    if (relative == NULL) {
        return false;
    }
    *outRelativeFilename = relative;
    return true;
}

// Formats a byte count of elapsed steady-clock time as "NdNNhNNmNNs" (only
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

// Builds the JSON body served by GET /health and GET /metrics (Task 3) - the
// SAME data PrintHealthSnapshot() below prints as plain text for the 'm'
// keypress (Task 2), so the two can never drift apart (both read
// g_scTransport.GetMetrics() and g_scMaxHubConnections directly, nothing is
// cached/duplicated). Deliberately plain, hand-built JSON (no third-party
// JSON library - see this repo's existing "dependency-free where reasonable"
// pattern, e.g. config.h/config.cpp's own INI-like format) - the shape is
// simple enough (flat, all-numeric-or-string fields) that string
// concatenation is clearer here than pulling in a library for it.
static std::string BuildHealthJson() {
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
        "\"sc_tx_bytes\":%llu"
        "}",
        (unsigned long long)uptime, FormatUptime(uptime).c_str(),
        m.currentPeerCount, (unsigned)g_scMaxHubConnections,
        (unsigned long long)m.totalConnects, (unsigned long long)m.totalDisconnects,
        (unsigned long long)m.rateLimitRejections,
        (unsigned long long)m.rxMessages, (unsigned long long)m.rxBytes,
        (unsigned long long)m.txMessages, (unsigned long long)m.txBytes);
    return std::string(buf);
}

// Plain-text health/metrics snapshot for the 'm' keypress (Task 2) - same
// fields as BuildHealthJson() above, formatted for a human reading stdout
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
// given/invalid. Same pattern as ParseScPortArg above (Task 3).
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

// Parse "--sc-rate-limit <n>" (0..65535; 0 = no limit); returns defaultValue
// if not given/invalid. Same pattern as ParseScMaxHubConnectionsArg above
// (Task 2), except 0 is a valid, meaningful value here (see g_scRateLimit's
// comment) so the lower bound check is ">= 0" (i.e. no lower bound at all)
// rather than "> 0".
static uint16_t ParseScRateLimitArg(const int argc, char** argv, const uint16_t defaultValue) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--sc-rate-limit") == 0) {
            char* end = NULL;
            const long value = strtol(argv[i + 1], &end, 10);
            if (end != argv[i + 1] && *end == '\0' && value >= 0 && value <= 65535) {
                return (uint16_t)value;
            }
            printf("Warning: ignoring invalid --sc-rate-limit \"%s\" (want 0..65535); using %u.\n",
                   argv[i + 1], (unsigned)defaultValue);
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

static bool HasFlag(const int argc, char** argv, const char* flagName) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], flagName) == 0) {
            return true;
        }
    }
    return false;
}

int main(int argc, char** argv) {
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
    // see g_dccPassword's own comment and README.md "Secrets handling").
    if (CASExampleHelper::HandleHelpAndVersionArgs(argc, argv, APP_NAME, APP_VERSION,
                                                   /*showDccPasswordCliOption*/ false)) {
        // common/'s --help handler cannot know about this example's BACnet/SC
        // options (see the file header) - print them here too, but only for
        // --help/-h//? (not --version, which HandleHelpAndVersionArgs also
        // handles and which should stay just a version string).
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "/?") == 0) {
                printf("\nBACnet/SC options (NM-SCH-B hub function):\n");
                printf("  --sc-port <n>       WebSocket/TLS port for the hub accept URI. Default 47819.\n");
                printf("  --sc-cert-dir <dir> Directory holding hub.crt/hub.key/ca.crt (see\n");
                printf("                      scripts/generate-test-certs.cmake). Default \"./certs\".\n");
                printf("  --sc-hub-uri <wss://host:port/path>\n");
                printf("                      Also run the hub CONNECTOR role: dial out to another hub at\n");
                printf("                      this URI. Off by default (this example needs only the hub\n");
                printf("                      FUNCTION/listener role above for NM-SCH-B).\n");
                printf("  --sc-failover-uri <wss://host:port/path>\n");
                printf("                      Optional failover hub URI, used only if --sc-hub-uri is\n");
                printf("                      also given.\n");
                printf("  --sc-max-hub-connections <n>\n");
                printf("                      Max simultaneous inbound BACnet/SC peer connections the hub\n");
                printf("                      function accepts (enforced by the stack). Default 4.\n");
                printf("  --sc-rate-limit <n>\n");
                printf("                      Max NEW inbound BACnet/SC connection ATTEMPTS/second the\n");
                printf("                      listener accepts before rejecting the excess (before the TLS\n");
                printf("                      handshake - enforced by this example's transport, not the\n");
                printf("                      stack). Distinct from --sc-max-hub-connections, which bounds\n");
                printf("                      CONCURRENT connections, not the rate of new attempts. 0 = no\n");
                printf("                      limit. Default 10.\n");
                printf("\nLab certificates (LAB TESTING ONLY - written to --sc-cert-dir, then exits):\n");
                printf("  --generate-certs [n]\n");
                printf("                      Create a fresh set: a lab CA (ca.crt/ca.key), this hub's\n");
                printf("                      certificate (hub.crt/hub.key/hub.csr) and n labeled client\n");
                printf("                      certificates for the devices that connect to the hub\n");
                printf("                      (client-01.crt/.key, ...). Default n = 3. Refuses to replace\n");
                printf("                      an existing CA unless --force is also given.\n");
                printf("  --add-client-certs [n]\n");
                printf("                      Sign n more client certificates (default 1) with the CA\n");
                printf("                      already in --sc-cert-dir. Numbering continues after the\n");
                printf("                      highest existing label, and the running hub trusts them\n");
                printf("                      without a restart.\n");
                printf("  --cert-label <prefix>\n");
                printf("                      Label for client certificates. Default \"client\", giving\n");
                printf("                      client-01, client-02, ... Each certificate's Common Name is\n");
                printf("                      \"Chipkin Example B-SCHUB <label>-NN\". Every certificate is\n");
                printf("                      also listed in <sc-cert-dir>/certificates.txt.\n");
                printf("  --force             With --generate-certs: delete the old set first.\n");
                printf("\nHTTP health/metrics + certificate upload (Tasks 3/4):\n");
                printf("  --http-port <n>     TCP port for the read-only GET /health, GET /metrics and\n");
                printf("                      POST /certs/<slot> HTTP endpoints. Default 8080.\n");
                printf("                      GET /health and GET /metrics need no authentication.\n");
                printf("                      POST /certs/<slot> (slot: operational, csr, issuer1, issuer2)\n");
                printf("                      requires \"Authorization: Bearer <dcc-password>\" and is\n");
                printf("                      DISABLED ENTIRELY if dcc-password is not set - see\n");
                printf("                      README.md \"Certificate upload endpoint\".\n");
                printf("  --http-bind <addr>  Interface the HTTP endpoints above bind to. Default\n");
                printf("                      127.0.0.1 (loopback only). Binding anywhere else (e.g.\n");
                printf("                      0.0.0.0, or a LAN address) is a real security tradeoff -\n");
                printf("                      this listener has NO TLS, and GET /health, GET /metrics have\n");
                printf("                      NO authentication at all - see README.md \"Health/metrics\n");
                printf("                      HTTP endpoint\" before setting this to anything else.\n");
                printf("\nConfig file:\n");
                printf("  --config <path>     Read defaults for device-id, port, sc-port, sc-cert-dir,\n");
                printf("                      sc-hub-uri, sc-failover-uri, dcc-password, http-port,\n");
                printf("                      http-bind, sc-max-hub-connections and sc-rate-limit from a\n");
                printf("                      \"key = value\" file (see example.conf and README.md\n");
                printf("                      \"Configuration file\"). Any of those flags given on the\n");
                printf("                      command line still wins over the config file - EXCEPT\n");
                printf("                      dcc-password, which has NO command-line flag at all (Task 1:\n");
                printf("                      see README.md \"Secrets handling\").\n");
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

    const uint16_t port = CASExampleHelper::ParsePortArg(
        argc, argv, fileConfig.hasPort ? fileConfig.port : 47808);
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
            const bool ok = generate
                ? CertTool::GenerateCertificateSet(g_scCertDir, generateCount, label, HasFlag(argc, argv, "--force"))
                : CertTool::AddClientCertificates(g_scCertDir, addCount, label);
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
    g_scMaxHubConnections = ParseScMaxHubConnectionsArg(
        argc, argv, fileConfig.hasScMaxHubConnections ? fileConfig.scMaxHubConnections : SC_MAX_HUB_CONNECTIONS_DEFAULT);
    g_scRateLimit = ParseScRateLimitArg(
        argc, argv, fileConfig.hasScRateLimit ? fileConfig.scRateLimit : SC_RATE_LIMIT_DEFAULT);
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
    // the file header note.
    if (!g_scRouter.Start(port)) {
        return 1;
    }

    g_bacnetIpUdpPort = port;
    if (!CASExampleHelper::GetLocalIPv4(g_ipAddress, g_ipSubnetMask)) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                              "could not read a local IPv4 address; Network Port IP_Address "
                              "will report 0.0.0.0.");
    }

    // --- Configure the BACnet/SC transport -------------------------------------
    // Build the accept URI from --sc-port now that the CLI has been parsed.
    // "0.0.0.0" = bind every interface (ScTransport::StartListening's contract).
    g_scHubAcceptUri = "wss://0.0.0.0:" + std::to_string(g_scPort) + "/";
    {
        CASSc::ScTlsFiles tls;
        tls.caCertPath = g_scCertDir + "/ca.crt";
        tls.certPath = g_scCertDir + "/hub.crt";
        tls.keyPath = g_scCertDir + "/hub.key";
        g_scTransport.Configure(tls, "hub.bsc.bacnet.org"); // plan fact 1 - NOT "hub.bacnet.org"
        // Task 2: bound how fast the listener accepts new connection
        // ATTEMPTS - see g_scRateLimit's comment and
        // ScTransport::SetMaxConnectionAttemptsPerSecond's header comment for
        // why this is separate from g_scMaxHubConnections (below).
        g_scTransport.SetMaxConnectionAttemptsPerSecond(g_scRateLimit);
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

    // --- Create the device --------------------------------------------------
    if (!BACnetStack_AddDevice(g_deviceInstance)) {
        printf("Error: Failed to add the Device %u.\n", g_deviceInstance);
        return 1;
    }

    // Enable the services this B-SCHUB profile requires: ReadProperty (DS-RP-B),
    // ReadPropertyMultiple (DS-RPM-B), and DeviceCommunicationControl (DM-DCC-B).
    // We deliberately do NOT enable WriteProperty, SubscribeCOV, or any
    // alarm/event service - a BACnet/SC Hub does not require them, so a
    // faithful B-SCHUB example leaves them off.
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

    // --- Add the read-only sensor objects (base series pattern) -------------
    if (!BACnetStack_AddObject(g_deviceInstance, OBJECT_TYPE_ANALOG_INPUT, ANALOG_INPUT_INSTANCE)) {
        printf("Error: Failed to add Analog Input %u (Bronze).\n", ANALOG_INPUT_INSTANCE);
        return 1;
    }
    if (!BACnetStack_AddObject(g_deviceInstance, OBJECT_TYPE_BINARY_INPUT, BINARY_INPUT_INSTANCE)) {
        printf("Error: Failed to add Binary Input %u (Emerald).\n", BINARY_INPUT_INSTANCE);
        return 1;
    }
    if (!BACnetStack_AddObject(g_deviceInstance, OBJECT_TYPE_MULTI_STATE_INPUT, MULTI_STATE_INPUT_INSTANCE)) {
        printf("Error: Failed to add Multi-State Input %u (Hot Pink).\n", MULTI_STATE_INPUT_INSTANCE);
        return 1;
    }

    // --- Add Network Port 1 (BACnet/IP, "BACnet IP") -------------------------
    if (!BACnetStack_AddNetworkPortObject(
            g_deviceInstance, NETWORK_PORT_INSTANCE,
            NETWORK_PORT_NETWORK_TYPE_IPV4,
            NETWORK_PORT_PROTOCOL_LEVEL_BACNET_APPLICATION,
            0,  // networkNumber: not configured
            NETWORK_NUMBER_QUALITY_UNKNOWN,
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
            0, NETWORK_NUMBER_QUALITY_UNKNOWN,
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

    // --- Add the 4 read-only certificate/CSR File objects (phase 4) ---------
    // and bind them to Network Port 2's SC certificate properties. Content is
    // served from --sc-cert-dir by CallbackReadFile (section 2d) - never
    // hub.key. See the FILE_*_INSTANCE constants' own comment above for which
    // file each instance serves and why the two issuer slots are the same file
    // in this lab setup.
    if (!BACnetStack_AddFileObject(g_deviceInstance, FILE_OPERATIONAL_CERT_INSTANCE,
                                   /*isWritable*/ false, /*isConfigurationFile*/ false,
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
                                   /*isWritable*/ false, /*isConfigurationFile*/ false,
                                   FILE_ACCESS_METHOD_STREAM)) {
        printf("Error: Failed to add File %u (Issuer Certificate Slot 1, issuer certificate 1).\n", FILE_ISSUER_CERT_1_INSTANCE);
        return 1;
    }
    if (!BACnetStack_AddFileObject(g_deviceInstance, FILE_ISSUER_CERT_2_INSTANCE,
                                   /*isWritable*/ false, /*isConfigurationFile*/ false,
                                   FILE_ACCESS_METHOD_STREAM)) {
        printf("Error: Failed to add File %u (Issuer Certificate Slot 2, issuer certificate 2).\n", FILE_ISSUER_CERT_2_INSTANCE);
        return 1;
    }
    {
        // Exactly 2 issuer slots - the stack requires this regardless of how many
        // distinct CAs the lab setup actually has (see the FILE_ISSUER_CERT_2_INSTANCE
        // comment above: both slots point at the same certs/ca.crt here).
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
    if (!BACnetStack_SetPropertyEnabled(g_deviceInstance, OBJECT_TYPE_DEVICE,
                                        g_deviceInstance, PROPERTY_IDENTIFIER_DESCRIPTION, true)) {
        printf("Error: Failed to enable Description on the Device object.\n");
        return 1;
    }
    if (!BACnetStack_SetPropertyEnabled(g_deviceInstance, OBJECT_TYPE_MULTI_STATE_INPUT,
                                        MULTI_STATE_INPUT_INSTANCE, PROPERTY_IDENTIFIER_STATE_TEXT, true)) {
        printf("Error: Failed to enable State_Text on Multi-State Input 1 (Hot Pink).\n");
        return 1;
    }

    // Who-Is is answered automatically. The spec also requires a device to
    // announce itself on start-up, so broadcast an unsolicited I-Am now (to the
    // local subnet broadcast - the BACnet/IP Network Port's own network).
    // g_scRouter.SendIAm(), not CASExampleHelper::SendIAm() - the router owns
    // Network Port 1's UDP socket directly (see the "Bind the BACnet/IP
    // socket" comment above).
    g_scRouter.SendIAm(g_deviceInstance);

    printf("FYI: Device %u (\"%s\") ready. Vendor ID %u. Press 'h' for help, 'm' for a health/metrics snapshot.\n",
           g_deviceInstance, DEVICE_NAME, VENDOR_IDENTIFIER);
    printf("FYI: BACnet/SC hub function is CONFIGURED on Network Port %u "
           "(BACnet SC), accept URI %s. Certificates: %s. See README.md "
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
        httpConfig.bearerToken = g_dccPassword;  // Task 4: empty => upload endpoint disabled entirely
        httpConfig.resolveCertSlot = ResolveCertUploadSlot;
        httpConfig.buildHealthJson = BuildHealthJson;
        g_httpServer.Start(httpConfig);
    }

    // --- Run the stack ------------------------------------------------------
    bool running = true;
    while (running) {
        BACnetStack_Tick();

        // Pump the WebSocket/TLS transport non-blockingly, then report any
        // resulting connection-status changes to the stack. NEVER call
        // BACnetStack_* from inside an lws callback (plan fact 6) - Service()
        // only queues; DrainStatusEvents() is what actually calls
        // BACnetStack_SetBACnetSCWebSocketStatus, safely here in the main loop.
        g_scTransport.Service();
        g_scRouter.DrainStatusEvents();
        g_httpServer.Service(); // Tasks 3/4 - non-blocking, same mechanism as g_scTransport.Service()

        switch (CASExampleHelper::PollKey()) {
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
    return 0;
}
