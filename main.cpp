// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE. The CAS BACnet Stack itself is
// a separate, commercially licensed product and is not covered by CC0.
// =============================================================================
// BACnet Profile Example - B-SCHUB (BACnet/SC Hub) - C++
//
// THIS IS AN EXAMPLE, for evaluation and testing only: it shows how to build a
// BACnet/SC hub with the CAS BACnet Stack, accepts at most 4 BACnet/SC devices
// (SC_MAX_HUB_CONNECTIONS_LIMIT below) and stops after 24 hours
// (DEMO_RUN_LIMIT_SECONDS). For a production-ready BACnet/SC hub, see the
// Chipkin BACnet SC Hub product (PRODUCT_CONTACT below).
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
// It keeps the series' base sensor object, Analog Input 1, with its colour
// name (the convention shared across this example series). The Network Port
// and four File objects below deliberately break from that convention:
// they are purpose-named instead, because a BACnet/SC hub's operator-facing
// tooling (and this file's own comments) benefit far more from "which port is
// the SC one" and "which File is the CSR" being self-evident than from another
// colour:
//
//     Device 389022                 "Chipkin Example B-SCHUB"
//     Analog Input  1               "Bronze"                    (REAL, degrees Celsius; read-only)
//     Network Port 1                "BACnet IP"                 (only with --port: the optional BACnet/IP port)
//     Network Port 2                "BACnet SC"                 (the BACnet/SC port - hub function;
//                                                                 the data link without --port)
//     File 1                        "Operational Certificate"   (the hub's operational certificate,
//                                                                 cert1/device-<n>/port-2/opr-hub.pem; writable)
//     File 2                        "Certificate Signing Request" (the hub's CSR,
//                                                                 cert1/device-<n>/port-2/csr-hub.pem; read-only)
//     File 3                        "Issuer Certificate Slot 1" (cert1/issuer/iss-1.pem; writable)
//     File 4                        "Issuer Certificate Slot 2" (cert1/issuer/iss-2.pem, or slot 1's
//                                                                 certificate until one is written; writable)
//   The file names are the CARI layout (ANSI/ASHRAE 135-2024 Annex AA.2) - see
//   cert_layout.h.
//
// Every object has a Description saying what it is for (ObjectDescription()).
//
// This profile does NOT require WriteProperty, COV, alarms, scheduling or
// trending, so this example leaves those off. The only writes it accepts are
// the BACnet/SC certificate procedures (clause 19.8.3, section 2d-ii below) and
// the File objects' Archive flag (cl. 12.13: writable).
//
// -----------------------------------------------------------------------------
// BACNET/SC TRANSPORT (NM-SCH-B) - see sc_transport/README.md for the full
// design; this section is the summary.
//
// Read from submodules/cas-bacnet-stack/docs/CAS BACnet Stack - BACnet SC
// Manual_v6.md and the doc comments on every BACnetStack_*SC* / *Websocket*
// export in CASBACnetStackDLL.h (search "BACnetSC Functions"): the stack owns
// the BACnet/SC PROTOCOL - the Hello handshake, the hub function's state
// machine, BVLC framing, certificate-object bookkeeping, the SC Network Port
// properties. It does NOT own the transport. Verbatim, from the doc comment on
// BACnetStack_RegisterCallbackInitiateWebsocket:
//
//     "The stack implements no WebSocket or TLS itself."
//
// The stack asks the HOST to listen on, and close, raw WebSocket(+TLS)
// connections via callbacks (RegisterCallbackSCStartListening,
// RegisterCallbackSCStopListening, RegisterCallbackDisconnectWebsocket) and
// expects status reported back through BACnetStack_SetBACnetSCWebSocketStatus.
// This example supplies that transport for real: sc_transport/ScTransport
// (libwebsockets + OpenSSL, via vcpkg - mutual TLS 1.3, subprotocol
// "hub.bsc.bacnet.org", binary WebSocket framing, the 1600-byte ingress
// ceiling enforced) and sc_transport/ScTransportRouter (the stack<->transport
// glue, dispatching ReceiveMessageForPort/SendMessageForPort by Network Port
// instance).
//
// The hub function is the B-SCHUB profile's whole BACnet/SC role: devices
// connect to it and it relays their traffic. A hub does not need to dial out
// itself, so the hub CONNECTOR (RegisterCallbackInitiateWebsocket,
// BACnetStack_SetBACnetSCHubConnectorForNetworkPort) is configured only when
// --sc-hub-uri is given, to let this hub ALSO connect to another hub, with an
// optional --sc-failover-uri.
//
// By default there is NO BACnet/IP port: BACnet/SC is this device's only data
// link, so it is reachable only over BACnet/SC. Every service - Who-Is/I-Am
// included - reaches it through the hub function: a device connects to the hub
// and sends its requests there. With --port <n> the hub ALSO opens a BACnet/IP
// port (Network Port 1, UDP) - opt-in, for finding and managing the hub over
// plain BACnet/IP; ScTransportRouter dispatches between the two ports. The
// BACnet/SC Network Port keeps instance 2 (and the CARI port folder
// cert1/device-<n>/port-2/), so existing certificate sets keep working.
//
// Network Port 2's SC certificate properties (Operational_Certificate_File,
// Certificate_Signing_Request_File, Issuer_Certificate_Files) point at 4 File
// objects (see the object list above), served from --sc-cert-dir by
// RegisterCallbackReadFile (section 2d below) - never the private key (it has
// no File object at all). Certificate validation is entirely this example's
// job: the stack has no TLS path of its own and no certificate-validation
// callback. This device's certificate policy is CA-chain validation, performed
// by the TLS library (OpenSSL, via libwebsockets) at handshake time, plus
// revocation checking when a CRL (issuer-crl.pem) is installed. There is no
// UUID-in-SAN binding: BACnet/SC certificates identify devices, not DNS hosts.
// -----------------------------------------------------------------------------

#include "CASExampleHelper.h"
#include "CASExampleLog.h"
#include "CASBACnetStackExampleConstants.h"
#include "CASBACnetStackAdapter.h" // the CAS BACnet Stack C API (BACnetStack_*); call
                                    // LoadBACnetFunctions() before any BACnetStack_* call -
                                    // see the top of main() below.
#include "sc_transport/ScTransport.h"
#include "sc_transport/ScTransportRouter.h"
#include "sc_transport/KeyPassword.h" // the private key's password, asked for once
#include "cert_layout.h" // where each certificate file is in --sc-cert-dir (CARI tree)
#include "cert_tool.h"   // the start-up certificate request / --import-cari - see cert_tool.h
#include "cert_store.h"  // certificate File object contents + clause 19.8.3 staging - see cert_store.h
#include "log_file.h"    // logs/B-SCHUB.log: a copy of everything written to the console

// main.cpp needs the real libwebsockets.h for LwsLogCallback/lws_set_log_level
// below (sc_transport/ScTransport.h forward-declares the lws types instead).
#include <libwebsockets.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <chrono>
#include <string>
#include <sys/stat.h> // stat()/_stat() - the CRL file's fingerprint
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
static const char* APP_VERSION = "1.8.0";

// The device instance - this example's entry in the series' device-instance
// table, so several examples can run on one subnet at once.
// The series' device instance for B-SCHUB; --deviceID changes it, so two
// examples on one BACnet network can each have a unique instance.
static uint32_t g_deviceInstance = 389022;

// ---- Device identity: CHANGE ALL OF THIS BEFORE YOU SHIP --------------------
// Everything in this block is read by clients and shown to the operator in every
// discovery tool on the network. Left as-is, your product will appear on a real
// site announcing itself as a Chipkin example. None of it is cosmetic:
// Object_Name must be unique across the BACnet internetwork, and Model_Name /
// Vendor_Identifier are what a building operator uses to identify your device.
// -----------------------------------------------------------------------------

// Your BACnet Vendor Identifier. 389 = Chipkin Automation Systems; change this
// to YOUR company's vendor ID before shipping a product. Vendor IDs are assigned
// by ASHRAE - request one (free) at https://bacnet.org/assigned-vendor-ids/.
// Update VENDOR_NAME below to match.
static const uint32_t VENDOR_IDENTIFIER = 389;

// The Device object's Object_Name. It must be unique across the whole BACnet
// internetwork. The device instance is configurable with --deviceID, so it is
// easy to run two units with correct instances and still have BOTH announce the
// same Object_Name - a spec violation. So the name is configurable too:
// --device-name. DEVICE_NAME_DEFAULT is only what an unconfigured unit calls
// itself.
static const char* DEVICE_NAME_DEFAULT = "Chipkin Example B-SCHUB";
static std::string g_deviceName = DEVICE_NAME_DEFAULT;
// Longest --device-name accepted, in UTF-8 bytes. Object_Name has no fixed
// limit in the standard, but the stack reads it into a 256-byte buffer and
// fails one that fills it; 128 leaves plenty of room.
static const size_t MAX_DEVICE_NAME_BYTES = 128;

// Each Network Port's Network_Number (1..65534) - --ip-network-number (only
// with --port) / --sc-network-number. 0 = not configured: the port reports 0
// with Network_Number_Quality "unknown". When set, it is reported with quality
// "configured". This device isn't a router, so the number is informational - it
// records which BACnet network each port is on.
static uint16_t g_ipNetworkNumber = 0;
static uint16_t g_scNetworkNumber = 0;

// Device identity strings (read by clients, and used to populate I-Am).
//   VENDOR_NAME - your company name; it must match VENDOR_IDENTIFIER above.
//   MODEL_NAME  - your model designation. This is what a building operator reads
//                 to identify your device in a discovery tool.
static const char* VENDOR_NAME = "Chipkin Automation Systems";
static const char* MODEL_NAME = "CAS BACnet Stack Example - B-SCHUB";

// Application_Software_Version (12) is just APP_VERSION - one source of truth,
// so it can never drift from what --version and the start-up banner print.
//
// Firmware_Revision (44) names the underlying platform/stack, not this
// example's own version - built at runtime from the CAS BACnet Stack's own
// BACnetStack_GetAPIMajorVersion()/etc. (the same 4 calls
// common/CASExampleHelper.cpp's PrintVersion() uses for the start-up banner's
// "CAS BACnet Stack version: X.Y.Z.W" line), populated once right after
// LoadBACnetFunctions() succeeds.
static std::string g_firmwareRevision;

// The series' base sensor object (instance 1) and its colour name.
static const uint32_t ANALOG_INPUT_INSTANCE = 1;       // "Bronze"

// Network Port 1 - the OPTIONAL BACnet/IP port (UDP). The hub is BACnet/SC-only
// by default: Network Port 1 and its UDP socket exist only when --port <n> is
// given (g_bacnetIpEnabled), for finding and managing the hub over plain
// BACnet/IP. It is the port the pre-1.7 releases had.
static const uint32_t NETWORK_PORT_INSTANCE = 1;       // "BACnet IP"
static bool g_bacnetIpEnabled = false;                 // set by --port
static const uint32_t MAX_APDU_LENGTH = 1476;          // BACnet/IP APDU length

// Network Port 2 - the BACnet/SC port, hosting the hub function (NM-SCH-B).
// It keeps instance 2 - the CARI certificate tree names the port
// (cert1/device-<n>/port-2/), so certificate sets made for this example keep
// working.
// BACnetNetworkType::secureConnect = 11 (source/BACnetNetworkType.h). This is a
// LOCAL constant, not added to common/CASBACnetStackExampleConstants.h - that
// file is the series-wide vendored common/ helper (owned by B-SS-CPP; changing
// it is a separate, serialised change across the whole series). A single
// example needing one extra constant does not justify a common/ change.
static const uint8_t NETWORK_PORT_NETWORK_TYPE_SECURE_CONNECT = 11;
static const uint32_t SC_NETWORK_PORT_INSTANCE = 2;     // "BACnet SC"

// THE CONNECTION LIMIT. This example accepts at most 4 BACnet/SC devices at a
// time. The limit is a ceiling that cannot be raised: --sc-max-hub-connections
// may only LOWER it (1 to 4), and a larger value is refused at start-up. The
// value in force (g_scMaxHubConnections) is passed to
// BACnetStack_SetBACnetSCHubFunctionConfig in main(); the STACK enforces it: its
// hub function refuses a Connect-Request once the accepted-connection table
// holds this many devices - a BACnet/SC protocol-level refusal (the
// WebSocket/TLS handshake in sc_transport/ScTransport completes first; the
// stack answers the BVLC-SC Connect-Request that follows with a NAK). main()'s
// loop notices the refusal and logs CONNECTION_LIMIT_MESSAGE_FORMAT (at most
// once a minute).
static const uint16_t SC_MAX_HUB_CONNECTIONS_LIMIT = 4;
static uint16_t g_scMaxHubConnections = SC_MAX_HUB_CONNECTIONS_LIMIT;

// THE RUN LIMIT. This example stops by itself after 24 hours (exit code 0,
// with RUN_LIMIT_MESSAGE_FORMAT); restarting it starts a new 24 hours.
// Checked in main()'s loop against g_startTime.
//
// FOR AUTOMATED TESTS ONLY, the environment variable
// BSCHUB_TEST_RUN_LIMIT_SECONDS=<n> shortens it to n seconds (1 to
// DEMO_RUN_LIMIT_SECONDS) - it can never raise it. An environment variable,
// not a command-line option, so the example's command line stays small.
static const uint64_t DEMO_RUN_LIMIT_SECONDS = 24ULL * 60 * 60;
static const char* const TEST_RUN_LIMIT_VARIABLE = "BSCHUB_TEST_RUN_LIMIT_SECONDS";
static uint64_t g_runLimitSeconds = DEMO_RUN_LIMIT_SECONDS;

// What this example says about itself, and where to get a production hub (the
// Chipkin BACnet SC Hub product). The product is named ONLY in these three
// messages: the start-up banner, and the two limit messages - the connection
// limit refusing a device, and the run limit stopping the example. Each "%s"
// is the run limit ("24 hours").
#define PRODUCT_CONTACT \
    "For a production-ready BACnet/SC hub, the Chipkin BACnet SC Hub: Contact Chipkin sales@chipkin.com"
static const char* const STARTUP_BANNER_FORMAT =
    "This is an example of using the CAS BACnet Stack to build a BACnet/SC hub (B-SCHUB profile). "
    "It is for evaluation and testing only, not for production. It accepts at most 4 BACnet/SC devices "
    "and stops after %s. " PRODUCT_CONTACT;
// "%u" is the number of devices in force (4, or less with --sc-max-hub-connections).
static const char* const CONNECTION_LIMIT_MESSAGE_FORMAT =
    "This example accepts at most %u BACnet/SC devices; a device was refused. " PRODUCT_CONTACT;
static const char* const RUN_LIMIT_MESSAGE_FORMAT =
    "This example stops after %s; the time is up - stopping. Restart it to continue evaluating. " PRODUCT_CONTACT;

// How fast the hub-function listener accepts NEW inbound connection ATTEMPTS,
// enforced by sc_transport/ScTransport before the TLS handshake starts (see
// ScTransport::SetConnectionRateLimits). Distinct from the connection limit
// above, which bounds CONCURRENT connections.
//   SC_RATE_LIMIT_PER_ADDRESS_DEFAULT (--sc-rate-limit) - attempts/second from
//                               any ONE source address, so one flooding host
//                               can't starve devices on other addresses.
//   SC_RATE_LIMIT_TOTAL_DEFAULT (--sc-rate-limit-total) - attempts/second for
//                               the whole listener, a ceiling on a flood from
//                               many addresses.
// Both are generous: a device's own reconnect back-off is seconds, not
// milliseconds, so they only bite under a real flood. 0 turns a limit off.
static const uint16_t SC_RATE_LIMIT_PER_ADDRESS_DEFAULT = 10;
static const uint16_t SC_RATE_LIMIT_TOTAL_DEFAULT = 50;
static uint16_t g_scRateLimit = SC_RATE_LIMIT_PER_ADDRESS_DEFAULT;
static uint16_t g_scRateLimitTotal = SC_RATE_LIMIT_TOTAL_DEFAULT;

// BACnet/SC interoperability relaxations, both OFF by default. 135-2024 AB.2.2
// makes the Hello destination option mandatory on a Connect-Request and a
// Connect-Accept; some implementations (YABE, for one) leave it out. main() ORs
// the chosen bits into BACnetStack_SetBACnetSCCompatibilityFlags (device-wide):
//   SC_COMPATIBILITY_ACCEPT_CONNECT_ACCEPT_WITHOUT_HELLO (0x01,
//     --sc-accept-hub-without-hello): the hub CONNECTOR (--sc-hub-uri) accepts
//     a Connect-Accept without Hello from the hub it dials.
//   SC_COMPATIBILITY_ACCEPT_CONNECT_REQUEST_WITHOUT_HELLO (0x02,
//     --sc-accept-device-without-hello): the hub FUNCTION accepts a device's
//     Connect-Request without Hello - what YABE sends. The device's Hello
//     capabilities are recorded as 0.
// Each is a deliberate deviation from the standard: leave it off unless a
// specific peer needs it.
static const uint8_t SC_COMPATIBILITY_ACCEPT_CONNECT_ACCEPT_WITHOUT_HELLO = 0x01;
static const uint8_t SC_COMPATIBILITY_ACCEPT_CONNECT_REQUEST_WITHOUT_HELLO = 0x02;
static bool g_scAcceptDeviceWithoutHello = false;
static bool g_scAcceptHubWithoutHello = false;

// Device properties of the clock (DM-UTC-B) - local constants, as below: common/ has
// no UTC_Offset or Daylight_Savings_Status.
static const uint32_t PROPERTY_IDENTIFIER_DAYLIGHT_SAVINGS_STATUS = 24;
static const uint32_t PROPERTY_IDENTIFIER_UTC_OFFSET = 119;

// The 4 File objects Network Port 2's SC certificate properties point at - see
// BACnetStack_SetBACnetSCCertificateFileObjects's call in main() and
// RegisterCallbackReadFile in section 2d. Same "local constant, not common/"
// rationale as NETWORK_PORT_NETWORK_TYPE_SECURE_CONNECT above. Named for what
// each one is rather than a colour - see the file header note above for why.
static const uint32_t FILE_OPERATIONAL_CERT_INSTANCE = 1;  // "Operational Certificate"     - opr-hub.pem
static const uint32_t FILE_CSR_INSTANCE = 2;                // "Certificate Signing Request" - csr-hub.pem
static const uint32_t FILE_ISSUER_CERT_1_INSTANCE = 3;      // "Issuer Certificate Slot 1"   - iss-1.pem
static const uint32_t FILE_ISSUER_CERT_2_INSTANCE = 4;      // "Issuer Certificate Slot 2"   - iss-2.pem
                                                              // (BACnetStack_SetBACnetSCCertificateFileObjects
                                                              // requires exactly 2 issuer slots)
// File_Access_Method (135-2024 Table 12-16): 0 = Record Access, 1 = Stream Access
// (BACnetStack_AddFileObject's own doc comment). All 4 File objects above are stream access -
// there is no record structure to a PEM file.
static const uint8_t FILE_ACCESS_METHOD_STREAM = 1;

// BACnetObjectType::file (submodules/cas-bacnet-stack/source/BACnetObjectType.h) and the File
// object's own required-property identifiers (BACnetPropertyIdentifier.h) - none of these are in
// common/CASBACnetStackExampleConstants.h, so they are defined locally here.
static const uint16_t OBJECT_TYPE_FILE = 10;
static const uint32_t PROPERTY_IDENTIFIER_ARCHIVE = 13;
static const uint32_t PROPERTY_IDENTIFIER_FILE_SIZE = 42;
static const uint32_t PROPERTY_IDENTIFIER_FILE_TYPE = 43;
static const uint32_t PROPERTY_IDENTIFIER_MODIFICATION_DATE = 71;
static const uint32_t PROPERTY_IDENTIFIER_READ_ONLY = 99;

// Archive of each of the 4 File objects (cl. 12.13: writable). This hub does not
// act on it; it only holds the flag a client wrote, until the next start.
static bool g_fileArchive[4] = {false, false, false, false};

// AtomicReadFile (BACnetServicesSupported.h: atomicReadFile = 6) - its own
// confirmed service, NOT implied by adding a File object: without it a client's
// AtomicReadFile against the device times out rather than erroring.
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
// BACnetNetworkPortCommand values the stack forwards to NetworkPortCommand
// (cl. 12.56.16) - the rest it executes itself.
static const uint32_t NETWORK_PORT_COMMAND_DISCARD_CHANGES = 1;
static const uint32_t NETWORK_PORT_COMMAND_GENERATE_CSR_FILE = 9;

// Set by the ReinitializeDevice callback once new certificates are committed;
// the main loop then reloads the TLS contexts (see ScTransport::ReloadCredentials).
// That drops every connection - including the one the ReinitializeDevice came
// in on when it came over BACnet/SC - but only after the frames already queued
// (the acknowledgement) have gone out (ScTransport's kFlushBeforeClose).
static bool g_scReloadCredentialsRequested = false;

// The certificate revocation list file (issuer-crl.pem) - optional, see
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

// The BACnet/SC hub function's WebSocket/TLS listener (--sc-port) and the
// certificate folder (--sc-cert-dir).
static uint16_t g_scPort = 4443;
static std::string g_scCertDir = "./certs";
// Every certificate file's path in g_scCertDir (the CARI tree) - set once at
// start-up from cert_layout.h, used everywhere a certificate or key file is
// named.
static CertLayout::HubCertPaths g_certPaths;
// Built from g_scPort once the command line has been parsed - see main().
// "0.0.0.0" binds every interface (ScTransport::StartListening treats that
// host - or an empty one - as "bind all", the same as a NULL lws iface).
static std::string g_scHubAcceptUri;

// The BACnet/SC hub CONNECTOR (initiator) role - OFF unless --sc-hub-uri is
// given: BACnetStack_SetBACnetSCHubConnectorForNetworkPort rejects an empty
// primary URI, and a hub does not need a connector to answer the devices
// connected to it. With it, this hub ALSO dials out to another hub, with an
// optional failover (--sc-failover-uri).
static std::string g_scHubUri;      // primary hub URI to dial; empty = connector role off
static std::string g_scFailoverUri; // optional failover hub URI; empty = none configured

// Process start time (steady clock - immune to wall-clock adjustments),
// captured in main() - the uptime the 'm' console key prints.
static std::chrono::steady_clock::time_point g_startTime;

// The real WebSocket/TLS transport (sc_transport/ScTransport.h) and the glue
// that moves the stack's ReceiveMessageForPort/SendMessageForPort messages to
// and from it (sc_transport/ScTransportRouter.h). Both are globals (not
// locals in main()) because the BACnet/SC transport callbacks below - plain C
// function pointers the stack calls with no user-data argument - need to reach
// g_scTransport.
static CASSc::ScTransport g_scTransport;
// Declared after g_scTransport (intra-TU global init order follows
// declaration order, and this takes a reference to it - see
// ScTransportRouter.h's constructor).
static CASSc::ScTransportRouter g_scRouter(NETWORK_PORT_INSTANCE, SC_NETWORK_PORT_INSTANCE, g_scTransport);

// BACnet/IP addressing Network Port 1 reports (only with --port). The IP address
// and subnet mask are filled in at start-up from the host's primary interface;
// the gateway is left unset (0.0.0.0). The stack also uses IP_Address +
// BACnet_IP_UDP_Port to build the port's MAC_Address automatically.
static uint8_t g_ipAddress[4] = { 0, 0, 0, 0 };
static uint8_t g_ipSubnetMask[4] = { 0, 0, 0, 0 };
static uint8_t g_ipDefaultGateway[4] = { 0, 0, 0, 0 };
static uint16_t g_bacnetIpUdpPort = 47808;

// BACnet/SC device UUID (135-2024 AB.1.5.3) - REQUIRED, set exactly once. A
// real device should generate/persist a stable random UUID (RFC 4122 v4) per
// unit; this example uses a fixed, clearly-an-example value so every run is
// reproducible. CHANGE THIS before using the pattern on real hardware - two
// devices sharing a UUID is a protocol violation.
static const uint8_t SC_DEVICE_UUID[16] = {
    0x53, 0x43, 0x48, 0x55, 0x42, 0x2d, 0x44, 0x45,   // "SCHUB-DE"
    0x4d, 0x4f, 0x2d, 0x33, 0x38, 0x39, 0x30, 0x32    // "MO-38902" (-> ...389022)
};

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
// 2a-i. File object helpers - map a File object instance to the file it serves
// under --sc-cert-dir, and read that file's size/bytes/mtime. Shared by
// GetPropertyCharString/UnsignedInteger/Bool/Date/Time and
// RegisterCallbackReadFile below (section 2d). NEVER lists the private key
// here - it has no File object and is never reachable through any of these.
// -----------------------------------------------------------------------------

// True if fileInstance is one of the 4 certificate/CSR File objects above.
static bool IsScCertFileInstance(const uint32_t fileInstance) {
    return fileInstance == FILE_OPERATIONAL_CERT_INSTANCE || fileInstance == FILE_CSR_INSTANCE ||
           fileInstance == FILE_ISSUER_CERT_1_INSTANCE || fileInstance == FILE_ISSUER_CERT_2_INSTANCE;
}

// Full on-disk path for one of the 4 File object instances above, or "" if
// fileInstance isn't one of them. The files are the hub's CARI tree
// (cert1/device-<n>/port-2/opr-hub.pem ...) - g_certPaths (cert_layout.h)
// knows their names.
static std::string ScCertFilePath(const uint32_t fileInstance) {
    switch (fileInstance) {
        case FILE_OPERATIONAL_CERT_INSTANCE: return g_certPaths.operationalCertificate;
        case FILE_CSR_INSTANCE:              return g_certPaths.certificateSigningRequest;
        case FILE_ISSUER_CERT_1_INSTANCE:    return g_certPaths.issuerCertificate1;
        // Slot 2 has its own file, so a client can add a second issuer
        // without overwriting slot 1. Until something is written to it, it
        // serves slot 1's certificate (CertStore's read fallback).
        case FILE_ISSUER_CERT_2_INSTANCE:    return g_certPaths.issuerCertificate2;
        default:                             return std::string();
    }
}

// Stats the file for a File object instance. Returns false (leaving *size/*mtime
// untouched) if it isn't one of the 4 File objects or the file can't be stat'd
// (e.g. --sc-cert-dir doesn't have it yet - the same "certificates missing"
// case ScTransport reports for the listener).
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
    if (g_bacnetIpEnabled && objectType == OBJECT_TYPE_NETWORK_PORT &&
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
    if (g_bacnetIpEnabled && objectType == OBJECT_TYPE_NETWORK_PORT && objectInstance == NETWORK_PORT_INSTANCE) {
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

// The Device's clock state (DM-TS-B, DM-UTC-B) - see "The Device's clock" below.
static time_t g_clockOffsetSeconds = 0;   // seconds the device clock is from the host clock (UTC)
static int32_t g_utcOffsetMinutes = 0;    // UTC_Offset
static bool g_daylightSavings = false;    // Daylight_Savings_Status

// BOOLEAN - Out_Of_Service is a required property of every input object and of
// the Network Port. This is a read-only sensor, so nothing is ever out of
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
    // The Device's Daylight_Savings_Status (cl. 12.11.26), part of the clock above.
    if (objectType == OBJECT_TYPE_DEVICE && objectInstance == g_deviceInstance &&
        propertyIdentifier == PROPERTY_IDENTIFIER_DAYLIGHT_SAVINGS_STATUS) {
        *value = g_daylightSavings;
        return true;
    }
    // Archive / Read_Only (both required; no stack default). Read_Only mirrors the
    // isWritable given to BACnetStack_AddFileObject: the operational and issuer
    // certificate files are writable (clause 19.8.3 certificate procedures), the
    // Certificate Signing Request is not. Archive is writable on every File object
    // (cl. 12.13, conformance code W): a client marks a file archived, and the flag
    // is only stored (see SetPropertyBool).
    if (objectType == OBJECT_TYPE_FILE && IsScCertFileInstance(objectInstance)) {
        if (propertyIdentifier == PROPERTY_IDENTIFIER_ARCHIVE) {
            *value = g_fileArchive[objectInstance - FILE_OPERATIONAL_CERT_INSTANCE];
            return true;
        }
        if (propertyIdentifier == PROPERTY_IDENTIFIER_READ_ONLY) {
            *value = (objectInstance == FILE_CSR_INSTANCE);
            return true;
        }
    }
    return false;
}

// The Device's clock (DM-TS-B and DM-UTC-B: the TimeSynchronization and
// UTCTimeSynchronization services). The device keeps UTC - the host's clock plus
// g_clockOffsetSeconds, the correction the last synchronization applied
// (SetSystemTime below) - and the time zone it is in:
//
//   UTC_Offset               g_utcOffsetMinutes: minutes between local STANDARD
//                            time and UTC, west of Greenwich positive (cl. 12.11.25)
//   Daylight_Savings_Status  g_daylightSavings: TRUE while daylight saving time is
//                            in effect (cl. 12.11.26)
//
// so that  Local_Date / Local_Time = UTC - UTC_Offset (+ 1 hour while the status is
// TRUE). Both start from the host's time zone (InitTimeZoneFromHost; UTC and FALSE
// when the host's cannot be determined) and are writable over BACnet (UTC_Offset
// "shall be configurable", cl. 12.11.25): writing UTC_Offset changes the local time
// and leaves UTC alone. They are state, not rules: the example does not follow a
// daylight saving transition on its own - write Daylight_Savings_Status when it
// happens. A device with a real-time clock would set that clock instead of keeping
// an offset. GetClock is also the time the stack reads for its timeouts and
// subscriptions, so a synchronization moves those too.
static CASBACnetTime GetClock() {
    return (CASBACnetTime)(time(NULL) + g_clockOffsetSeconds);
}

// Calendar time <-> seconds, both in UTC (the "local" fields below are just a
// calendar; the host's own time zone does not take part).
static time_t CalendarToSeconds(struct tm* calendar) {
#if defined(_WIN32)
    return _mkgmtime(calendar);
#else
    return timegm(calendar);
#endif
}

static bool SecondsToCalendar(const time_t seconds, struct tm* out) {
#if defined(_WIN32)
    return gmtime_s(out, &seconds) == 0;
#else
    return gmtime_r(&seconds, out) != NULL;
#endif
}

// Seconds on the device's local wall clock for a UTC instant (cl. 12.11.25/.26).
static time_t LocalSecondsFromUtc(const time_t utcSeconds) {
    return utcSeconds - (time_t)g_utcOffsetMinutes * 60 + (g_daylightSavings ? 3600 : 0);
}

static bool GetCurrentLocalTm(struct tm* out) {
    return SecondsToCalendar(LocalSecondsFromUtc((time_t)GetClock()), out);
}

// Sets UTC_Offset and Daylight_Savings_Status from the host's time zone, once, at
// start-up. UTC_Offset is the standard-time offset (the host's daylight saving
// hour taken out), rounded to a multiple of 15 minutes, within -1440..+1440.
static void InitTimeZoneFromHost() {
    g_utcOffsetMinutes = 0;
    g_daylightSavings = false;
    const time_t now = time(NULL);
    struct tm hostLocal;
#if defined(_WIN32)
    const bool haveLocal = localtime_s(&hostLocal, &now) == 0;
#else
    const bool haveLocal = localtime_r(&now, &hostLocal) != NULL;
#endif
    if (!haveLocal) {
        return;
    }
    const bool dst = hostLocal.tm_isdst > 0;
    struct tm asCalendar = hostLocal; // the host's local fields read as if they were UTC
    asCalendar.tm_isdst = 0;
    const time_t localAsUtc = CalendarToSeconds(&asCalendar);
    if (localAsUtc == (time_t)-1) {
        return;
    }
    long eastSeconds = (long)(localAsUtc - now) - (dst ? 3600 : 0); // standard time, east of Greenwich positive
    long minutes = -eastSeconds / 60;                               // BACnet: west positive
    minutes = (minutes >= 0 ? (minutes + 7) / 15 : -((-minutes + 7) / 15)) * 15;
    if (minutes < -1440 || minutes > 1440) {
        return;
    }
    g_utcOffsetMinutes = (int32_t)minutes;
    g_daylightSavings = dst;
}

// TimeSynchronization (DM-TS-B, cl. 16.7) and UTCTimeSynchronization (DM-UTC-B,
// cl. 16.8): the stack decodes the request, refuses a date or time with an
// unspecified field or a day the month does not have, and - for the UTC service -
// subtracts UTC_Offset from the UTC and allows for Daylight_Savings_Status (both
// read back through GetPropertySignedInteger / GetPropertyBool below). What it
// passes here is the LOCAL date and time to set. Both services are unconfirmed, so
// a refused request is dropped without a reply. The clock is set so that
// Local_Date / Local_Time read exactly that, with UTC_Offset and
// Daylight_Savings_Status unchanged.
bool SetSystemTime(const uint32_t deviceInstance, const uint8_t year, const uint8_t month,
                   const uint8_t day, const uint8_t weekday, const uint8_t hour,
                   const uint8_t minute, const uint8_t second, const uint8_t hundredthSecond) {
    (void)weekday;
    (void)hundredthSecond;
    if (deviceInstance != g_deviceInstance) {
        return false;
    }
    const uint8_t UNSPECIFIED = 255;
    if (year == UNSPECIFIED || month == UNSPECIFIED || day == UNSPECIFIED ||
        hour == UNSPECIFIED || minute == UNSPECIFIED || second == UNSPECIFIED) {
        printf("SetSystemTime: ignored - the date or time has an unspecified field\n");
        return false;
    }
    struct tm requested;
    memset(&requested, 0, sizeof(requested));
    requested.tm_year = year; // BACnet years count from 1900, as struct tm does
    requested.tm_mon = month - 1;
    requested.tm_mday = day;
    requested.tm_hour = hour;
    requested.tm_min = minute;
    requested.tm_sec = second;
    const time_t requestedLocal = CalendarToSeconds(&requested);
    if (requestedLocal == (time_t)-1) {
        printf("SetSystemTime: ignored - not a valid date and time\n");
        return false;
    }
    const time_t requestedUtc = requestedLocal + (time_t)g_utcOffsetMinutes * 60 - (g_daylightSavings ? 3600 : 0);
    g_clockOffsetSeconds = requestedUtc - time(NULL);
    printf("SetSystemTime: local %04u-%02u-%02u %02u:%02u:%02u (UTC_Offset %d min, daylight saving %s; "
           "the device clock is now %lld s from the host clock)\n",
           1900u + year, month, day, hour, minute, second, (int)g_utcOffsetMinutes,
           g_daylightSavings ? "on" : "off", (long long)g_clockOffsetSeconds);
    return true;
}

// The Device's UTC_Offset (Integer). The only SignedInteger property this device
// serves.
bool GetPropertySignedInteger(const uint32_t deviceInstance, const uint16_t objectType,
                              const uint32_t objectInstance, const uint32_t propertyIdentifier,
                              int32_t* value, const bool useArrayIndex,
                              const uint32_t propertyArrayIndex, uint32_t* errorCode) {
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    (void)errorCode;
    if (deviceInstance != g_deviceInstance || objectType != OBJECT_TYPE_DEVICE ||
        objectInstance != g_deviceInstance || propertyIdentifier != PROPERTY_IDENTIFIER_UTC_OFFSET) {
        return false;
    }
    *value = g_utcOffsetMinutes;
    return true;
}

// WriteProperty on UTC_Offset: any multiple of 15 minutes from -1440 to +1440
// (cl. 12.11.25); anything else is value-out-of-range. UTC stays where it is, so
// Local_Date / Local_Time move.
bool SetPropertySignedInteger(const uint32_t deviceInstance, const uint16_t objectType,
                              const uint32_t objectInstance, const uint32_t propertyIdentifier,
                              const int32_t value, const bool useArrayIndex,
                              const uint32_t propertyArrayIndex, const uint8_t priority,
                              uint32_t* errorCode) {
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    (void)priority;
    if (deviceInstance != g_deviceInstance || objectType != OBJECT_TYPE_DEVICE ||
        objectInstance != g_deviceInstance || propertyIdentifier != PROPERTY_IDENTIFIER_UTC_OFFSET) {
        return false;  // the stack answers write-access-denied
    }
    if (value < -1440 || value > 1440 || value % 15 != 0) {
        *errorCode = ERROR_CODE_VALUE_OUT_OF_RANGE;
        return false;
    }
    g_utcOffsetMinutes = value;
    CASExampleHelper::Log(CASExampleHelper::LogLevel::Info, "WriteProperty Device UTC_Offset = %d", (int)value);
    return true;
}

// DATE / TIME - together they answer Modification_Date (BACnetDateTime) of the
// 4 File objects (the stack calls both callbacks with propertyIdentifier ==
// PROPERTY_IDENTIFIER_MODIFICATION_DATE for the one BACnetDateTime read; required,
// no stack default - the real on-disk mtime of the file, in UTC) and the
// Device's Local_Date and Local_Time (the clock above).
bool GetPropertyDate(const uint32_t deviceInstance, const uint16_t objectType,
                     const uint32_t objectInstance, const uint32_t propertyIdentifier,
                     uint8_t* yearMinus1900, uint8_t* month, uint8_t* day, uint8_t* weekday,
                     const bool useArrayIndex, const uint32_t propertyArrayIndex, uint32_t* errorCode) {
    (void)errorCode;
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    if (deviceInstance == g_deviceInstance && objectType == OBJECT_TYPE_DEVICE &&
        objectInstance == g_deviceInstance && propertyIdentifier == PROPERTY_IDENTIFIER_LOCAL_DATE) {
        struct tm nowTm;
        if (!GetCurrentLocalTm(&nowTm)) {
            return false;
        }
        *yearMinus1900 = (uint8_t)nowTm.tm_year;
        *month = (uint8_t)(nowTm.tm_mon + 1);
        *day = (uint8_t)nowTm.tm_mday;
        *weekday = (uint8_t)(nowTm.tm_wday == 0 ? 7 : nowTm.tm_wday); // BACnet Weekday: Monday=1..Sunday=7
        return true;
    }
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
    if (deviceInstance == g_deviceInstance && objectType == OBJECT_TYPE_DEVICE &&
        objectInstance == g_deviceInstance && propertyIdentifier == PROPERTY_IDENTIFIER_LOCAL_TIME) {
        struct tm nowTm;
        if (!GetCurrentLocalTm(&nowTm)) {
            return false;
        }
        *hour = (uint8_t)nowTm.tm_hour;
        *minute = (uint8_t)nowTm.tm_min;
        *second = (uint8_t)nowTm.tm_sec;
        *hundredthSecond = 0;
        return true;
    }
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

// OCTET STRING - the BACnet/IP Network Port's addressing (only with --port). The
// stack cannot know the host's IP, so the application must supply IP_Address and
// IP_Subnet_Mask (and IP_Default_Gateway). Each is four octets. The stack also
// reads IP_Address (with BACnet_IP_UDP_Port) to build the port's six-octet
// MAC_Address.
bool GetPropertyOctetString(const uint32_t deviceInstance, const uint16_t objectType,
                            const uint32_t objectInstance, const uint32_t propertyIdentifier,
                            uint8_t* value, uint32_t* valueElementCount,
                            const uint32_t maxElementCount, const bool useArrayIndex,
                            const uint32_t propertyArrayIndex, uint32_t* errorCode) {
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    (void)errorCode;
    if (!g_bacnetIpEnabled || deviceInstance != g_deviceInstance ||
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

// Description (optional property) of each object: what it is for in this
// example. Kept under ~250 characters - a longer string than the stack's
// character-string buffer aborts the read instead of truncating (found on
// B-BC). Returns "" for an object this device doesn't have.
static std::string ObjectDescription(const uint16_t objectType, const uint32_t objectInstance) {
    if (objectType == OBJECT_TYPE_DEVICE && objectInstance == g_deviceInstance) {
        return std::string("CAS BACnet Stack example: a BACnet/SC hub (B-SCHUB profile), ") +
               (g_bacnetIpEnabled ? "with a BACnet/IP port (--port). " : "reachable over BACnet/SC only. ") +
               "For evaluation and testing only.";
    }
    if (objectType == OBJECT_TYPE_NETWORK_PORT && objectInstance == NETWORK_PORT_INSTANCE) {
        return "BACnet/IP port (UDP), so this hub can also be found and managed over plain BACnet/IP.";
    }
    if (objectType == OBJECT_TYPE_ANALOG_INPUT && objectInstance == ANALOG_INPUT_INSTANCE) {
        return "Example sensor value in degrees C, showing a hub serving its own data. "
               "Change it with the up/down arrow keys in the console.";
    }
    if (objectType == OBJECT_TYPE_NETWORK_PORT && objectInstance == SC_NETWORK_PORT_INSTANCE) {
        return "BACnet/SC port: the hub function (the wss:// listener that devices connect to) and, if "
               "configured, the hub connector. "
               "Its certificates are File objects 1-4.";
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

// Small helper: copy a C string into the stack's character-string buffer and
// set the element count + encoding. Returns true (so callers can `return`).
static bool ReturnCharacterString(const char* text, char* value,
                                  uint32_t* valueElementCount,
                                  const uint32_t maxElementCount,
                                  uint8_t* encodingType) {
    uint32_t length = (uint32_t)strlen(text);
    // The stack fails a string that fills its whole buffer (stack issue
    // #2487), so leave at least one byte free - and never cut a multi-byte
    // UTF-8 character in half. Every string this example serves is well under
    // the limit, so this only guards against surprises.
    if (maxElementCount > 0 && length >= maxElementCount) {
        length = maxElementCount - 1;
        while (length > 0 && (((unsigned char)text[length]) & 0xC0) == 0x80) {
            --length;  // text[length] is a continuation byte: back up to a character start
        }
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
    // convention); a purpose name for the Network Port and File objects
    // (deliberately not a colour - see the file header note).
    if (propertyIdentifier == PROPERTY_IDENTIFIER_OBJECT_NAME) {
        if (objectType == OBJECT_TYPE_DEVICE && objectInstance == g_deviceInstance) {
            return ReturnCharacterString(g_deviceName.c_str(), value, valueElementCount, maxElementCount, encodingType);
        }
        if (objectType == OBJECT_TYPE_ANALOG_INPUT && objectInstance == ANALOG_INPUT_INSTANCE) {
            return ReturnCharacterString("Bronze", value, valueElementCount, maxElementCount, encodingType);
        }
        if (g_bacnetIpEnabled && objectType == OBJECT_TYPE_NETWORK_PORT && objectInstance == NETWORK_PORT_INSTANCE) {
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
// 2b. DeviceCommunicationControl callback (DM-DCC-B).
//
// A management station sends DeviceCommunicationControl to tell a device to stop
// or resume communicating - useful to quiet a noisy device during commissioning.
// The CAS BACnet Stack runs the actual enable/disable state machine (and the
// optional re-enable timer) for us; this callback's job is to decide whether to
// accept the request and let the application know what was asked. This example
// sets no password, so it accepts any request. A real device would check
// `password` against its own secret and answer ERROR_CODE_PASSWORD_FAILURE when
// it doesn't match - and note it crosses the wire in plaintext, so it is a guard
// against accidents, not a security boundary.
//
// NOTE (Protocol_Revision >= 20): the plain "disable" value (1) is DEPRECATED.
// Even if this callback accepts it, the stack rejects the request with
// service-request-denied - the standard now expects "disable-initiation" (2).
// -----------------------------------------------------------------------------
bool DeviceCommunicationControl(const uint32_t deviceInstance, const uint8_t enableDisable,
                                const char* password, const uint8_t passwordLength,
                                const bool useTimeDuration, const uint16_t timeDuration,
                                uint32_t* errorCode) {
    (void)password;        // no password in this example - see above
    (void)passwordLength;
    if (deviceInstance != g_deviceInstance) {
        *errorCode = ERROR_CODE_OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED;
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
// The stack drives the SC protocol and asks the HOST to actually accept and
// close WebSocket(+TLS) connections through these callbacks; each one below is
// a thin forward to g_scTransport (sc_transport/ScTransport.h). The stack owns
// the URI strings' storage only for the duration of the call, so every forward
// below copies into a std::string before calling into ScTransport (which may
// keep/compare the string afterwards).
// -----------------------------------------------------------------------------

// The stack asks us to OPEN an outbound WebSocket/TLS connection to a URI - the
// hub CONNECTOR/initiator role. Forwards to ScTransport::Connect(); only
// reached when --sc-hub-uri configured the connector role (see main()'s
// BACnetStack_SetBACnetSCHubConnectorForNetworkPort call). The stack discards
// this return value for the hub-connector path anyway; ScTransport::Connect()
// still returns honestly (true only if the connection ATTEMPT actually started).
bool CallbackInitiateWebsocket(const char* websocketUri, const uint32_t websocketUriLength) {
    const std::string uri(websocketUri, websocketUriLength);
    return g_scTransport.Connect(uri);
}

// The stack asks us to CLOSE a connection - an outbound hub URI, or an accepted
// device's "<acceptUri>|client=N" connection string (sc_transport/README.md
// fact 2).
void CallbackDisconnectWebsocket(const char* websocketUri, const uint32_t websocketUriLength) {
    const std::string uri(websocketUri, websocketUriLength);
    g_scTransport.Disconnect(uri);
}

// The stack asks us to START ACCEPTING inbound WebSocket connections on a URI -
// the hub function's accept role (NM-SCH-B). This can fire synchronously from
// inside BACnetStack_AddBACnetSCAcceptUri() (called from main() below), and the
// stack retries every Tick() while this returns false -
// ScTransport::StartListening() implements exactly that contract (returns
// false + logs once if the certificate files are missing, retried silently
// after that).
bool CallbackSCStartListening(const char* websocketUri, const uint32_t websocketUriLength) {
    const std::string uri(websocketUri, websocketUriLength);
    return g_scTransport.StartListening(uri);
}

// The stack asks us to STOP accepting inbound connections on a URI.
void CallbackSCStopListening(const char* websocketUri, const uint32_t websocketUriLength) {
    const std::string uri(websocketUri, websocketUriLength);
    g_scTransport.StopListening(uri);
}

// Purely observational: logs every BACnet/SC connection-state transition, so
// the state machine can be watched as devices connect and disconnect.
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
// 2d. File objects - AtomicReadFile for the 4 certificate/CSR File objects
// Network Port 2's SC certificate properties point at (see
// BACnetStack_SetBACnetSCCertificateFileObjects in main()). NEVER serves the
// private key - see the file header and each function's own comment below.
// -----------------------------------------------------------------------------

// Serves AtomicReadFile against the 4 File objects above by reading the actual
// bytes of the file ScCertFilePath maps that instance to, under --sc-cert-dir.
// Every one of those 4 files is a public certificate or a CSR - never the
// private key (key-hub.pem has no File object at all, so there is no
// fileInstance value that reaches it). Any other File object instance -
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
// Certificate Signing Request (File 2) is read-only - the hub writes it itself
// on GENERATE_CSR_FILE (NetworkPortCommand below).
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

// WriteProperty on a BOOLEAN property. Two are writable in this device: a File
// object's Archive (cl. 12.13, conformance code W; the flag is stored and read
// back, nothing else depends on it) and the Device's Daylight_Savings_Status
// (cl. 12.11.26; it moves Local_Time by an hour and leaves UTC alone - see the
// clock above).
bool SetPropertyBool(const uint32_t deviceInstance, const uint16_t objectType,
                     const uint32_t objectInstance, const uint32_t propertyIdentifier,
                     const bool value, const bool useArrayIndex,
                     const uint32_t propertyArrayIndex, const uint8_t priority,
                     uint32_t* errorCode) {
    (void)useArrayIndex;
    (void)propertyArrayIndex;
    (void)priority;
    (void)errorCode;
    if (deviceInstance == g_deviceInstance && objectType == OBJECT_TYPE_DEVICE &&
        objectInstance == g_deviceInstance && propertyIdentifier == PROPERTY_IDENTIFIER_DAYLIGHT_SAVINGS_STATUS) {
        g_daylightSavings = value;
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Info, "WriteProperty Device Daylight_Savings_Status = %s",
                              value ? "TRUE" : "FALSE");
        return true;
    }
    if (deviceInstance != g_deviceInstance || objectType != OBJECT_TYPE_FILE ||
        propertyIdentifier != PROPERTY_IDENTIFIER_ARCHIVE || !IsScCertFileInstance(objectInstance)) {
        return false;  // the stack answers write-access-denied
    }
    g_fileArchive[objectInstance - FILE_OPERATIONAL_CERT_INSTANCE] = value;
    CASExampleHelper::Log(CASExampleHelper::LogLevel::Info, "WriteProperty File %u Archive = %s", objectInstance,
                          value ? "TRUE" : "FALSE");
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
// is not restarted: "warm start" here means "apply the pending changes". Like
// DeviceCommunicationControl, this example sets no password - a real device
// guards ReinitializeDevice with one.
bool ReinitializeDevice(const uint32_t deviceInstance, const uint32_t reinitializedState,
                        const char* password, const uint32_t passwordLength, uint32_t* errorCode) {
    (void)password;        // no password in this example - see DeviceCommunicationControl
    (void)passwordLength;
    if (deviceInstance != g_deviceInstance) {
        *errorCode = ERROR_CODE_OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED;
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

// Network Port Command (cl. 12.56.16). The stack executes the
// Command property itself and asks the application about the two commands
// that touch data only the application holds:
//   DISCARD_CHANGES (1) - before the stack reverts its own pending changes.
//     The staged certificate writes are thrown away (cl. 12.56.100/.101
//     "revert the file data"). Answering true lets the stack finish the revert.
//   GENERATE_CSR_FILE (9) - the BACnet/SC port, only when Changes_Pending is
//     FALSE. A new key pair and Certificate Signing Request (File 2); the new
//     key stays pending until a certificate for it is activated - see
//     cert_store.h. Synchronous: P-256 generation takes milliseconds.
bool NetworkPortCommand(const uint32_t deviceInstance, const uint32_t networkPortInstance,
                        const uint32_t command, uint32_t* errorCode) {
    if (deviceInstance != g_deviceInstance) {
        *errorCode = ERROR_CODE_OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED;
        return false;
    }
    if (command == NETWORK_PORT_COMMAND_DISCARD_CHANGES) {
        if (networkPortInstance == SC_NETWORK_PORT_INSTANCE && CertStore::HasStagedChanges()) {
            CertStore::DiscardStaged();
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                                  "Network Port %u Command DISCARD_CHANGES: staged certificate writes discarded",
                                  networkPortInstance);
        } else {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                                  "Network Port %u Command DISCARD_CHANGES", networkPortInstance);
        }
        return true;
    }
    if (command == NETWORK_PORT_COMMAND_GENERATE_CSR_FILE && networkPortInstance == SC_NETWORK_PORT_INSTANCE) {
        std::string reason;
        if (!CertStore::GenerateKeyAndCsr(&reason)) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                                  "Network Port %u Command GENERATE_CSR_FILE: FAILED: %s",
                                  networkPortInstance, reason.c_str());
            *errorCode = ERROR_CODE_INVALID_CONFIGURATION_DATA;
            return false;
        }
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                              "Network Port %u Command GENERATE_CSR_FILE: new key pair and certificate signing "
                              "request (File %u) - the hub keeps its current key until a certificate for the new "
                              "one is activated", networkPortInstance, FILE_CSR_INSTANCE);
        return true;
    }
    *errorCode = ERROR_CODE_OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED;
    return false;
}

// -----------------------------------------------------------------------------
// 2e. The 'm' console key: BACnet/SC connection and traffic counters.
// -----------------------------------------------------------------------------

// "1d 2h 3m 4s" - only the units actually needed.
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

// The counters ScTransport keeps (ScTransport::GetMetrics()), for a human
// reading the console.
static void PrintConnectionCounters() {
    const CASSc::ScTransportMetrics m = g_scTransport.GetMetrics();
    const uint64_t uptime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - g_startTime).count());
    printf("--- BACnet/SC counters ---------------------------------------------------\n");
    printf("Uptime:                        %s\n", FormatUptime(uptime).c_str());
    printf("BACnet/SC listener:            %s\n",
           g_scTransport.IsListening() ? g_scTransport.ListenUri().c_str() : "NOT listening (see the certificate messages)");
    printf("BACnet/SC devices connected:   %zu of at most %u\n", m.acceptedPeerCount, (unsigned)g_scMaxHubConnections);
    printf("BACnet/SC connects total:      %llu\n", (unsigned long long)m.totalConnects);
    printf("BACnet/SC disconnects total:   %llu\n", (unsigned long long)m.totalDisconnects);
    printf("BACnet/SC devices refused:     %llu\n", (unsigned long long)m.connectRequestsRefused);
    printf("BACnet/SC rate-limit rejects:  %llu\n", (unsigned long long)m.rateLimitRejections);
    printf("BACnet/SC RX: %llu message(s), %llu byte(s)\n",
           (unsigned long long)m.rxMessages, (unsigned long long)m.rxBytes);
    printf("BACnet/SC TX: %llu message(s), %llu byte(s)\n",
           (unsigned long long)m.txMessages, (unsigned long long)m.txBytes);
    printf("BACnet/SC transmit-queue-full closes: %llu\n", (unsigned long long)m.txQueueOverflows);
    printf("------------------------------------------------------------------------\n");
}

// -----------------------------------------------------------------------------
// 2f. libwebsockets logging integration. lws's own internal debug/warning/error
// lines (e.g. "lws_tls_server_accept: client cert CN '...'") would otherwise
// print however lws's build configured them - unformatted, no timestamp, not
// through CASExampleHelper::Log. lws_set_log_level(level, callback) in main()
// routes them through the SAME facility every other log line uses.
//
// Level choice: LLL_ERR | LLL_WARN | LLL_NOTICE - lws's own build default
// ("err, warn, notice", per lws_set_log_level's doc comment in lws-logs.h).
// Deliberately NOT LLL_DEBUG/LLL_PARSER/etc - those are lws's per-frame/
// per-byte protocol trace, far too noisy for a tutorial's log output.
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
// 2g. Windows 10 notice.
//
// BACnet/SC requires TLS 1.3. The hub itself is fine on Windows 10 - it uses
// OpenSSL - but Windows' own TLS stack (Schannel) only makes TLS 1.3 client
// connections from Windows 11 / Server 2022 (build 22000) on. So BACnet/SC
// tools on a Windows 10 computer that use Windows' TLS, such as YABE, fail
// the handshake with this hub (and any conformant hub). Warn once at start-up
// so that failure isn't a mystery.
//
// RtlGetVersion, not GetVersionEx: without a compatibility manifest,
// GetVersionEx reports Windows 8 on every later version.
// -----------------------------------------------------------------------------

static void WarnIfWindows10() {
#if defined(_WIN32)
    typedef LONG(WINAPI * RtlGetVersionFn)(OSVERSIONINFOEXW*);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const RtlGetVersionFn rtlGetVersion =
        ntdll != NULL ? reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion")) : NULL;
    OSVERSIONINFOEXW version;
    memset(&version, 0, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    if (rtlGetVersion == NULL || rtlGetVersion(&version) != 0 || version.dwMajorVersion != 10) {
        return;  // can't tell (or not a 10.x kernel) - say nothing rather than guess
    }
    // Windows 10 and 11 share major version 10; so do Windows Server
    // 2016/2019/2022/2025. TLS 1.3 client support arrived with Windows 11
    // (build 22000) and Windows Server 2022 (build 20348).
    const bool isServer = version.wProductType != VER_NT_WORKSTATION;
    const DWORD firstBuildWithTls13 = isServer ? 20348 : 22000;
    if (version.dwBuildNumber < firstBuildWithTls13) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "This computer runs %s (build %lu). The hub works, but BACnet/SC tools on this computer "
            "that use Windows' own TLS (for example YABE) can't connect: BACnet/SC requires TLS 1.3, and "
            "this Windows version can't make TLS 1.3 client connections. Use Windows 11 / Server 2022 or "
            "later for those tools, or a client with its own TLS 1.3 (CAS BACnet Explorer). See README.md, "
            "\"Testing with YABE\".",
            isServer ? "a Windows Server version older than 2022" : "Windows 10",
            version.dwBuildNumber);
    }
#endif
}

// -----------------------------------------------------------------------------
// 3. main()
// -----------------------------------------------------------------------------

// The command line. Every option the example knows is listed here, so a typo
// or a value left off is an error instead of being silently ignored.
static const char* const kValueOptions[] = {
    "--port", "--sc-port", "--sc-cert-dir", "--import-cari", "--deviceID", "--device-name",
    "--ip-network-number", "--sc-network-number", "--sc-hub-uri", "--sc-failover-uri",
    "--sc-max-hub-connections", "--sc-rate-limit", "--sc-rate-limit-total"};
// Switches that also take an optional on/off (see ParseSwitchArg).
static const char* const kOnOffSwitches[] = {"--sc-accept-device-without-hello", "--sc-accept-hub-without-hello"};
static const char* const kSwitches[] = {"--help", "-h", "/?", "--version"};

static bool IsOneOf(const char* arg, const char* const* list, const size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(arg, list[i]) == 0) {
            return true;
        }
    }
    return false;
}

// "on"/"off" and friends, case-insensitively. Returns false if `text` is none of them.
static bool ParseOnOff(std::string text, bool* out) {
    for (char& c : text) {
        c = (char)tolower((unsigned char)c);
    }
    if (text == "on" || text == "true" || text == "yes" || text == "1") {
        *out = true;
        return true;
    }
    if (text == "off" || text == "false" || text == "no" || text == "0") {
        *out = false;
        return true;
    }
    return false;
}

// False (after printing why) if argv has an unknown option, a stray argument,
// or an option missing its value.
static bool ValidateCommandLine(const int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        bool unused = false;
        if (IsOneOf(arg, kValueOptions, sizeof(kValueOptions) / sizeof(kValueOptions[0]))) {
            if (i + 1 >= argc || strncmp(argv[i + 1], "--", 2) == 0) {
                fprintf(stderr, "Error: %s needs a value.\n", arg);
                return false;
            }
            ++i;
        } else if (IsOneOf(arg, kOnOffSwitches, sizeof(kOnOffSwitches) / sizeof(kOnOffSwitches[0]))) {
            if (i + 1 < argc && ParseOnOff(argv[i + 1], &unused)) {
                ++i;
            }
        } else if (!IsOneOf(arg, kSwitches, sizeof(kSwitches) / sizeof(kSwitches[0]))) {
            fprintf(stderr, "Error: unknown %s \"%s\" - see --help.\n", arg[0] == '-' ? "option" : "argument", arg);
            return false;
        }
    }
    return true;
}

static bool HasFlag(const int argc, char** argv, const char* flagName) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], flagName) == 0) {
            return true;
        }
    }
    return false;
}

// Parse "<flagName> <value>"; returns "" if not given.
static std::string ParseStringArg(const int argc, char** argv, const char* flagName) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], flagName) == 0) {
            return std::string(argv[i + 1]);
        }
    }
    return std::string();
}

// Parse "<flagName> <n>" (1..65535). Returns false (after printing why) if the
// value is not a valid port; leaves *port alone if the flag is not given.
static bool ParsePortOption(const int argc, char** argv, const char* flagName, uint16_t* port) {
    const std::string text = ParseStringArg(argc, argv, flagName);
    if (text.empty()) {
        return true;
    }
    char* end = NULL;
    const long value = strtol(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != '\0' || value <= 0 || value > 65535) {
        fprintf(stderr, "Error: %s expects a port number from 1 to 65535, got \"%s\".\n", flagName, text.c_str());
        return false;
    }
    *port = (uint16_t)value;
    return true;
}

// Parse "<flagName> <n>" (min..max). Returns false (after printing why) if the
// value is not a whole number in range; leaves *out alone if the flag is not
// given.
static bool ParseUIntOption(const int argc, char** argv, const char* flagName, const long min, const long max,
                            uint16_t* out) {
    const std::string text = ParseStringArg(argc, argv, flagName);
    if (text.empty()) {
        return true;
    }
    char* end = NULL;
    const long value = strtol(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != '\0' || value < min || value > max) {
        fprintf(stderr, "Error: %s expects a whole number from %ld to %ld, got \"%s\".\n", flagName, min, max,
                text.c_str());
        return false;
    }
    *out = (uint16_t)value;
    return true;
}

// True if `text` is well-formed UTF-8 (the encoding Object_Name is served in).
static bool IsValidUtf8(const std::string& text) {
    size_t i = 0;
    while (i < text.size()) {
        const unsigned char lead = (unsigned char)text[i];
        size_t extra;
        if (lead < 0x80) {
            extra = 0;
        } else if ((lead & 0xE0) == 0xC0) {
            extra = 1;
        } else if ((lead & 0xF0) == 0xE0) {
            extra = 2;
        } else if ((lead & 0xF8) == 0xF0) {
            extra = 3;
        } else {
            return false;
        }
        if (i + extra >= text.size()) {
            return false;  // truncated sequence
        }
        for (size_t k = 1; k <= extra; ++k) {
            if ((((unsigned char)text[i + k]) & 0xC0) != 0x80) {
                return false;
            }
        }
        i += extra + 1;
    }
    return true;
}

// "<flag>" alone means on; "<flag> on|off" sets it either way. Absent: off.
static bool ParseSwitchArg(const int argc, char** argv, const char* flagName) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], flagName) == 0) {
            bool value = true;
            if (i + 1 < argc && ParseOnOff(argv[i + 1], &value)) {
                return value;
            }
            return true;
        }
    }
    return false;
}

// The hub URI a device on the LAN dials: this machine's IPv4 address and
// --sc-port. The start-up certificate request asks for its host.
static std::string LanHubUri() {
    uint8_t ip[4] = {127, 0, 0, 1};
    uint8_t mask[4] = {0, 0, 0, 0};
    if (!CASExampleHelper::GetLocalIPv4(ip, mask)) {
        ip[0] = 127; ip[1] = 0; ip[2] = 0; ip[3] = 1;
    }
    char uri[64];
    snprintf(uri, sizeof(uri), "wss://%u.%u.%u.%u:%u/", ip[0], ip[1], ip[2], ip[3], g_scPort);
    return uri;
}

// The run limit for messages: "24 hours", or "5s"-style for a shortened test
// limit (BSCHUB_TEST_RUN_LIMIT_SECONDS) that isn't whole hours.
static std::string FormatRunLimit(const uint64_t seconds) {
    if (seconds % 3600 == 0) {
        const uint64_t hours = seconds / 3600;
        return std::to_string(hours) + (hours == 1 ? " hour" : " hours");
    }
    return FormatUptime(seconds);
}

// An environment variable's value, or "" if it isn't set.
static std::string EnvironmentVariable(const char* name) {
#if defined(_WIN32)
    char* value = NULL;
    size_t length = 0;
    std::string result;
    if (_dupenv_s(&value, &length, name) == 0 && value != NULL) {
        result = value;
    }
    free(value);
    return result;
#else
    const char* value = getenv(name);
    return value != NULL ? std::string(value) : std::string();
#endif
}

// Where this example lives - in --help.
static const char* const REPOSITORY_URL = "https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP";

static void PrintUsage() {
    CASExampleHelper::PrintVersion(APP_NAME, APP_VERSION);
    printf("\n");
    printf("An example of a BACnet/SC hub (B-SCHUB profile) on the CAS BACnet Stack, for evaluation\n");
    printf("and testing only. Reachable over BACnet/SC only, unless --port adds a BACnet/IP port.\n");
    printf("Source, documentation and updates: %s\n", REPOSITORY_URL);
    printf("\n");
    printf("Usage: BACnetExampleBSCHUB [options]\n");
    printf("\n");
    printf("Options:\n");
    printf("  --sc-cert-dir <dir> The certificate folder, a CARI tree (ANSI/ASHRAE 135-2024\n");
    printf("                      Annex AA.2): cert1/device-%u/port-2/opr-hub.pem, key-hub.pem,\n",
           g_deviceInstance);
    printf("                      csr-hub.pem and cert1/issuer/iss-1.pem. Default \"./certs\"\n");
    printf("                      (the demo certificates that come with this example).\n");
    printf("  --deviceID <n>      Device instance, unique on the BACnet network. Default 389022.\n");
    printf("  --device-name <name>\n");
    printf("                      The Device object's Object_Name, unique on the BACnet internetwork\n");
    printf("                      (1 to %u bytes of UTF-8). Default \"%s\".\n", (unsigned)MAX_DEVICE_NAME_BYTES,
           DEVICE_NAME_DEFAULT);
    printf("  --port <n>          Also open a BACnet/IP port (Network Port 1) on this UDP port,\n");
    printf("                      for finding and managing the hub over plain BACnet/IP (47808 is\n");
    printf("                      the usual one). Off by default: without it the hub is reachable\n");
    printf("                      only over BACnet/SC.\n");
    printf("  --ip-network-number <n>, --sc-network-number <n>\n");
    printf("                      The BACnet network number (1 to 65534) of Network Port 1 (only with\n");
    printf("                      --port) and of the BACnet/SC port. Reported as configured; the\n");
    printf("                      default is none (0, quality unknown). This device is not a router.\n");
    printf("  --sc-port <n>       BACnet/SC (WebSocket/TLS) port devices connect to. Default 4443.\n");
    printf("  --sc-max-hub-connections <n>\n");
    printf("                      Accept at most this many BACnet/SC devices (1 to %u, the default).\n",
           (unsigned)SC_MAX_HUB_CONNECTIONS_LIMIT);
    printf("                      The limit can only be lowered: this example never accepts more.\n");
    printf("  --sc-rate-limit <n>, --sc-rate-limit-total <n>\n");
    printf("                      New BACnet/SC connection attempts accepted per second from one\n");
    printf("                      address (default %u) and in total (default %u); 0 = no limit.\n",
           (unsigned)SC_RATE_LIMIT_PER_ADDRESS_DEFAULT, (unsigned)SC_RATE_LIMIT_TOTAL_DEFAULT);
    printf("  --sc-hub-uri <wss://host:port/path>\n");
    printf("                      Also connect to another BACnet/SC hub (the hub connector): dial\n");
    printf("                      this primary hub, so this hub's devices reach that hub's network.\n");
    printf("  --sc-failover-uri <wss://host:port/path>\n");
    printf("                      The failover hub, used only if the primary hub (--sc-hub-uri)\n");
    printf("                      cannot be reached.\n");
    printf("  --sc-accept-device-without-hello [on|off]\n");
    printf("                      Compatibility, off by default: accept a device whose\n");
    printf("                      Connect-Request omits the Hello option the standard requires\n");
    printf("                      (YABE does). Deviates from ANSI/ASHRAE 135 AB.2.2.\n");
    printf("  --sc-accept-hub-without-hello [on|off]\n");
    printf("                      Compatibility, off by default: the hub connector accepts a hub\n");
    printf("                      whose Connect-Accept omits the Hello option. Deviates from\n");
    printf("                      ANSI/ASHRAE 135 AB.2.2.\n");
    printf("  --import-cari <zip> Install a CA's CARI response (the hub's certificate and the\n");
    printf("                      issuer certificates) in the certificate folder, then exit.\n");
    printf("                      The certificate must be for this hub's request and signed by\n");
    printf("                      an issuer in the zip.\n");
    printf("  --help, -h          Show this help and exit.\n");
    printf("  --version           Show version information and exit.\n");
    printf("\n");
    printf("Files:\n");
    printf("  <sc-cert-dir>/%s (default ./certs/%s)\n", CertTool::HUB_REQUEST_ZIP, CertTool::HUB_REQUEST_ZIP);
    printf("                      This hub's certificate request, to send to a Certificate\n");
    printf("                      Authority. Created at start-up if it doesn't already exist\n");
    printf("                      (never overwritten; delete it to make a new one). A hub with no\n");
    printf("                      private key also gets a new key and request (key-hub.pem,\n");
    printf("                      csr-hub.pem); an existing key is never replaced.\n");
    printf("  %s/%s    A copy of everything shown on the console, in the folder the\n",
           LogFile::LOG_FOLDER, LogFile::LOG_FILE_NAME);
    printf("                      example runs in. Emptied at each start-up; send it to support.\n");
    printf("\n");
    printf("Commands (while it runs):\n");
    printf("  h     - show this help (version + commands)\n");
    printf("  q     - quit\n");
    printf("  up    - increase Analog Input 1 by 1.1\n");
    printf("  down  - decrease Analog Input 1 by 1.1\n");
    printf("  m     - show the BACnet/SC connection and traffic counters\n");
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

    // g_firmwareRevision (Device object property 44) - the STACK's version, not
    // this example's own (that's Application_Software_Version/APP_VERSION).
    // Must happen after LoadBACnetFunctions() (these getters ARE some of the
    // functions it loads) and before the Device object is ever readable.
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                 BACnetStack_GetAPIMajorVersion(), BACnetStack_GetAPIMinorVersion(),
                 BACnetStack_GetAPIPatchVersion(), BACnetStack_GetAPIBuildVersion());
        g_firmwareRevision = buf;
    }

    // --- Command line ---------------------------------------------------------
    if (!ValidateCommandLine(argc, argv)) {
        return 1;
    }
    if (HasFlag(argc, argv, "--help") || HasFlag(argc, argv, "-h") || HasFlag(argc, argv, "/?")) {
        PrintUsage();
        return 0;
    }
    if (HasFlag(argc, argv, "--version")) {
        CASExampleHelper::PrintVersion(APP_NAME, APP_VERSION);
        return 0;
    }

    // --- The log file -----------------------------------------------------------
    // From here on, everything written to the console - this example's lines,
    // the CAS BACnet Stack's and libwebsockets' - is copied to
    // logs/B-SCHUB.log in the folder the example runs in, emptied at each
    // start-up, so it can be sent to support. See log_file.h. If the file
    // can't be made, the example still runs and logs to the console only.
    std::string logFilePath;
    const bool logging = LogFile::Start(LogFile::LOG_FOLDER, LogFile::LOG_FILE_NAME, &logFilePath);

    if (!ParsePortOption(argc, argv, "--sc-port", &g_scPort)) {
        return 1;
    }
    // --port turns the optional BACnet/IP port on (off by default).
    if (HasFlag(argc, argv, "--port")) {
        if (!ParsePortOption(argc, argv, "--port", &g_bacnetIpUdpPort)) {
            return 1;
        }
        g_bacnetIpEnabled = true;
    }
    g_deviceInstance = CASExampleHelper::ParseDeviceIdArg(argc, argv, g_deviceInstance);
    if (HasFlag(argc, argv, "--sc-cert-dir")) {
        g_scCertDir = ParseStringArg(argc, argv, "--sc-cert-dir");
    }
    if (g_scCertDir.empty()) {
        // Every path is built as g_scCertDir + "/<file>", so "" would mean the
        // filesystem root (and the start-up certificate request would go there).
        fprintf(stderr, "Error: the certificate folder (--sc-cert-dir) is empty. Use \".\" for the current "
                        "folder.\n");
        return 1;
    }
    g_scAcceptDeviceWithoutHello = ParseSwitchArg(argc, argv, "--sc-accept-device-without-hello");
    g_scAcceptHubWithoutHello = ParseSwitchArg(argc, argv, "--sc-accept-hub-without-hello");

    // The hub extras: device name, network numbers, the connection limit, the
    // rate limits and the hub connector. Every value is checked here, so a bad
    // one stops the start instead of being silently ignored.
    {
        const std::string deviceName = ParseStringArg(argc, argv, "--device-name");
        if (HasFlag(argc, argv, "--device-name")) {
            g_deviceName = deviceName;
            if (g_deviceName.empty() || g_deviceName.size() > MAX_DEVICE_NAME_BYTES || !IsValidUtf8(g_deviceName)) {
                fprintf(stderr, "Error: --device-name must be 1 to %u bytes of UTF-8 text (got %u bytes%s).\n",
                        (unsigned)MAX_DEVICE_NAME_BYTES, (unsigned)g_deviceName.size(),
                        IsValidUtf8(g_deviceName) ? "" : ", not valid UTF-8");
                return 1;
            }
        }
        if (!ParseUIntOption(argc, argv, "--ip-network-number", 1, 65534, &g_ipNetworkNumber) ||
            !ParseUIntOption(argc, argv, "--sc-network-number", 1, 65534, &g_scNetworkNumber) ||
            !ParseUIntOption(argc, argv, "--sc-rate-limit", 0, 65535, &g_scRateLimit) ||
            !ParseUIntOption(argc, argv, "--sc-rate-limit-total", 0, 65535, &g_scRateLimitTotal)) {
            return 1;
        }
        if (g_ipNetworkNumber != 0 && !g_bacnetIpEnabled) {
            fprintf(stderr, "Error: --ip-network-number applies to Network Port 1, which exists only with --port.\n");
            return 1;
        }
        if (g_ipNetworkNumber != 0 && g_ipNetworkNumber == g_scNetworkNumber) {
            fprintf(stderr, "Error: --ip-network-number and --sc-network-number must differ: two ports of one "
                            "device are on two different BACnet networks.\n");
            return 1;
        }
        // The connection limit may only be lowered: 1 to SC_MAX_HUB_CONNECTIONS_LIMIT.
        // A larger value is refused (loudly: this is an example, see PRODUCT_CONTACT).
        uint16_t requested = g_scMaxHubConnections;
        if (!ParseUIntOption(argc, argv, "--sc-max-hub-connections", 1, 65535, &requested)) {
            return 1;
        }
        if (requested > SC_MAX_HUB_CONNECTIONS_LIMIT) {
            fprintf(stderr, "Error: --sc-max-hub-connections %u: this example accepts at most %u BACnet/SC "
                            "devices, and the option can only lower that. " PRODUCT_CONTACT "\n",
                    (unsigned)requested, (unsigned)SC_MAX_HUB_CONNECTIONS_LIMIT);
            return 1;
        }
        g_scMaxHubConnections = requested;
        g_scHubUri = ParseStringArg(argc, argv, "--sc-hub-uri");
        g_scFailoverUri = ParseStringArg(argc, argv, "--sc-failover-uri");
        if (HasFlag(argc, argv, "--sc-failover-uri") && g_scHubUri.empty()) {
            fprintf(stderr, "Error: --sc-failover-uri needs --sc-hub-uri (the primary hub it takes over from).\n");
            return 1;
        }
        for (const std::string* uri : {&g_scHubUri, &g_scFailoverUri}) {
            if (!uri->empty() && uri->compare(0, 6, "wss://") != 0) {
                fprintf(stderr, "Error: a hub URI must be a wss://host:port/path URI (BACnet/SC requires TLS), "
                                "got \"%s\".\n", uri->c_str());
                return 1;
            }
        }
    }

    // The run limit, shortened for an automated test (see DEMO_RUN_LIMIT_SECONDS).
    {
        const std::string testLimit = EnvironmentVariable(TEST_RUN_LIMIT_VARIABLE);
        if (!testLimit.empty()) {
            char* end = NULL;
            const unsigned long long seconds = strtoull(testLimit.c_str(), &end, 10);
            if (end == testLimit.c_str() || *end != '\0' || seconds == 0 || seconds > DEMO_RUN_LIMIT_SECONDS) {
                fprintf(stderr, "Error: %s (for testing only) expects 1 to %llu seconds, got \"%s\".\n",
                        TEST_RUN_LIMIT_VARIABLE, (unsigned long long)DEMO_RUN_LIMIT_SECONDS, testLimit.c_str());
                return 1;
            }
            g_runLimitSeconds = seconds;
        }
    }

    // --- The hub's own certificate (--import-cari) ------------------------------
    // A one-shot tool mode: do it, then exit without starting the device. The
    // hub never signs certificates; a Certificate Authority does. See cert_tool.h.
    {
        const std::string importFile = ParseStringArg(argc, argv, "--import-cari");
        if (!importFile.empty()) {
            return CertTool::ImportCariResponse(g_scCertDir, g_deviceInstance, importFile) ? 0 : 1;
        }
    }

    CASExampleHelper::PrintVersion(APP_NAME, APP_VERSION);
    // What this example is, and where to get a production hub - before "ready".
    printf("\n"
           "================================================================================\n");
    printf(STARTUP_BANNER_FORMAT, FormatRunLimit(g_runLimitSeconds).c_str());
    printf("\n"
           "================================================================================\n"
           "\n");
    if (logging) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                              "log file: \"%s\" (a copy of this console output, emptied at each start-up)",
                              logFilePath.c_str());
    }
    if (g_runLimitSeconds != DEMO_RUN_LIMIT_SECONDS) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                              "%s is set (for testing only): the run limit is %s.",
                              TEST_RUN_LIMIT_VARIABLE, FormatRunLimit(g_runLimitSeconds).c_str());
    }
    WarnIfWindows10();
    g_startTime = std::chrono::steady_clock::now();

    // Route libwebsockets' own internal logging through this app's log
    // facility, before ANY lws_context is created (the first one is
    // g_scTransport's, further down) - see LwsLogCallback's own comment above.
    lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE, &LwsLogCallback);

    // --- Bind the BACnet/IP socket (only with --port) ---------------------------
    // Owned by g_scRouter (sc_transport/ScTransportRouter.h), NOT
    // CASExampleHelper::SetupUDP() - the router's own ReceiveMessageForPort/
    // SendMessageForPort callbacks (registered below) must be able to reach
    // this socket directly to dispatch between it and BACnet/SC. Without --port
    // no socket is opened at all and the router only ever answers for
    // Network Port 2.
    if (g_bacnetIpEnabled) {
        if (!g_scRouter.Start(g_bacnetIpUdpPort)) {
            return 1;
        }
        if (!CASExampleHelper::GetLocalIPv4(g_ipAddress, g_ipSubnetMask)) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                                  "could not read a local IPv4 address; Network Port IP_Address "
                                  "will report 0.0.0.0.");
        }
    }

    // --- Configure the BACnet/SC transport -------------------------------------
    // Build the accept URI from --sc-port now that the command line has been
    // parsed. "0.0.0.0" = bind every interface (ScTransport::StartListening's
    // contract).
    g_scHubAcceptUri = "wss://0.0.0.0:" + std::to_string(g_scPort) + "/";
    // Where the certificate files are (the CARI tree - see cert_layout.h).
    // Said in the log, so it is clear which files the hub used.
    g_certPaths = CertLayout::ResolveHubCertPaths(g_scCertDir, g_deviceInstance);
    CASExampleHelper::Log(CASExampleHelper::LogLevel::Info, "certificates: CARI tree in \"%s\", hub port folder %s",
                          g_scCertDir.c_str(), g_certPaths.portFolder.c_str());
    if (!g_certPaths.note.empty()) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning, "certificates: %s", g_certPaths.note.c_str());
    }
    {
        // A password-protected private key: ask for its password ONCE, here,
        // before anything loads the key (CertStore just below, the certificate
        // check, the listener). See sc_transport/KeyPassword.h.
        std::string keyPasswordMessage;
        if (!CASSc::KeyPassword::Prepare(g_certPaths.privateKey, &keyPasswordMessage)) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Error, "certificates: %s", keyPasswordMessage.c_str());
        }

        // CertStore owns the 4 certificate File objects' contents (section 2d-ii).
        CertStore::Layout layout;
        const uint32_t certInstances[4] = {FILE_OPERATIONAL_CERT_INSTANCE, FILE_CSR_INSTANCE,
                                           FILE_ISSUER_CERT_1_INSTANCE, FILE_ISSUER_CERT_2_INSTANCE};
        for (const uint32_t instance : certInstances) {
            layout.paths[instance] = ScCertFilePath(instance);
        }
        layout.readFallbackInstances[FILE_ISSUER_CERT_2_INSTANCE] = FILE_ISSUER_CERT_1_INSTANCE;
        layout.operationalInstance = FILE_OPERATIONAL_CERT_INSTANCE;
        layout.issuerInstances = {FILE_ISSUER_CERT_1_INSTANCE, FILE_ISSUER_CERT_2_INSTANCE};
        layout.privateKeyPath = g_certPaths.privateKey;
        layout.pendingPrivateKeyPath = g_certPaths.pendingPrivateKey;
        layout.csrInstance = FILE_CSR_INSTANCE;
        CertStore::SetLayout(layout);
        std::string reconcileMessage;
        if (!CertStore::ReconcilePendingKey(&reconcileMessage)) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Error, "certificates: %s", reconcileMessage.c_str());
        } else if (!reconcileMessage.empty()) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning, "certificates: %s", reconcileMessage.c_str());
        }

        // The hub's CARI certificate request (hub-cari-request.zip), for a
        // Certificate Authority: made now if it doesn't exist, never
        // overwritten. A hub with no key at all also gets a new key and CSR;
        // an existing private key is never replaced. See cert_tool.h.
        std::string requestMessage;
        const CertTool::RequestResult request =
            CertTool::EnsureHubRequest(g_scCertDir, g_deviceInstance, g_deviceName, LanHubUri(), &requestMessage);
        CASExampleHelper::Log(request == CertTool::RequestResult::Failed ? CASExampleHelper::LogLevel::Warning
                                                                         : CASExampleHelper::LogLevel::Info,
                              "certificate request: %s", requestMessage.c_str());

        // TLS trusts every issuer in both slots. With no certificates yet, fall
        // back to slot 1's path so the "certificates missing" message names it.
        CASSc::ScTlsFiles tls;
        g_scTrustedIssuersPath = g_certPaths.trustedIssuers;
        std::string bundleReason;
        tls.caCertPath = CertStore::WriteTrustedIssuerBundle(g_scTrustedIssuersPath, &bundleReason)
                             ? g_scTrustedIssuersPath : ScCertFilePath(FILE_ISSUER_CERT_1_INSTANCE);
        tls.certPath = g_certPaths.operationalCertificate;
        tls.keyPath = g_certPaths.privateKey;
        // Optional certificate revocation list - see ScTlsFiles::crlPath.
        tls.crlPath = g_scCrlPath = g_certPaths.revocationList;
        g_scTransport.Configure(tls, "hub.bsc.bacnet.org"); // sc_transport/README.md fact 1 - NOT "hub.bacnet.org"
        // Bound how fast the listener accepts new connection attempts, per
        // source address and in total - see g_scRateLimit.
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
    // TimeSynchronization (DM-TS-B): the clock the stack reads, and the one it sets.
    BACnetStack_RegisterCallbackGetSystemTime(GetClock);
    BACnetStack_RegisterCallbackSetSystemTime(SetSystemTime);
    // DeviceCommunicationControl (DM-DCC-B).
    BACnetStack_RegisterCallbackDeviceCommunicationControl(DeviceCommunicationControl);
    // BACnet/SC transport callbacks (NM-SCH-B) - see section 2c above.
    BACnetStack_RegisterCallbackInitiateWebsocket(CallbackInitiateWebsocket);
    BACnetStack_RegisterCallbackDisconnectWebsocket(CallbackDisconnectWebsocket);
    BACnetStack_RegisterCallbackSCStartListening(CallbackSCStartListening);
    BACnetStack_RegisterCallbackSCStopListening(CallbackSCStopListening);
    BACnetStack_RegisterCallbackBACnetSCStateChange(CallbackBACnetSCStateChange);
    // AtomicReadFile for the 4 certificate File objects - see section 2d.
    BACnetStack_RegisterCallbackReadFile(CallbackReadFile);
    // Certificate writes over BACnet (clause 19.8.3) - see section 2d-ii.
    BACnetStack_RegisterCallbackWriteFile(CallbackWriteFile);
    BACnetStack_RegisterCallbackSetPropertyUnsignedInteger(SetPropertyUnsignedInteger);
    BACnetStack_RegisterCallbackSetPropertyBool(SetPropertyBool);
    // UTC_Offset (DM-UTC-B): the Device's only Integer property.
    BACnetStack_RegisterCallbackGetPropertySignedInteger(GetPropertySignedInteger);
    BACnetStack_RegisterCallbackSetPropertySignedInteger(SetPropertySignedInteger);
    BACnetStack_RegisterCallbackReinitializeDevice(ReinitializeDevice);
    // Network Port Command DISCARD_CHANGES / GENERATE_CSR_FILE - see 2d-ii.
    BACnetStack_RegisterCallbackNetworkPortCommand(NetworkPortCommand);

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
    // callbacks already registered above for ReadProperty (the stack resolves
    // each requested property through the identical path it uses for a
    // single-property ReadProperty). No additional callback is needed for RPM.
    if (!BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_READ_PROPERTY_MULTIPLE, true)) {
        printf("Error: Failed to enable the ReadPropertyMultiple service.\n");
        return 1;
    }
    if (!BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_DEVICE_COMMUNICATION_CONTROL, true)) {
        printf("Error: Failed to enable the DeviceCommunicationControl service.\n");
        return 1;
    }
    // AtomicReadFile - required for the 4 certificate File objects to actually
    // answer reads; see SERVICE_ATOMIC_READ_FILE's own comment above.
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

    // TimeSynchronization (DM-TS-B). The stack then lists Local_Date and Local_Time
    // in the Device's Property_List; GetPropertyDate / GetPropertyTime answer them.
    if (!BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_TIME_SYNCHRONIZATION, true)) {
        printf("Error: Failed to enable the TimeSynchronization service.\n");
        return 1;
    }

    // UTCTimeSynchronization (DM-UTC-B). The stack then also lists UTC_Offset and
    // Daylight_Savings_Status in the Device's Property_List; both are served and
    // writable (the clock above), and start from the host's time zone.
    InitTimeZoneFromHost();
    if (!BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_UTC_TIME_SYNCHRONIZATION, true)) {
        printf("Error: Failed to enable the UTCTimeSynchronization service.\n");
        return 1;
    }
    if (!BACnetStack_SetPropertyWritable(g_deviceInstance, OBJECT_TYPE_DEVICE, g_deviceInstance,
                                         PROPERTY_IDENTIFIER_UTC_OFFSET, true) ||
        !BACnetStack_SetPropertyWritable(g_deviceInstance, OBJECT_TYPE_DEVICE, g_deviceInstance,
                                         PROPERTY_IDENTIFIER_DAYLIGHT_SAVINGS_STATUS, true)) {
        printf("Error: Failed to make UTC_Offset and Daylight_Savings_Status writable.\n");
        return 1;
    }
    CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                          "Time zone from the host: UTC_Offset %d min, Daylight_Savings_Status %s",
                          (int)g_utcOffsetMinutes, g_daylightSavings ? "TRUE" : "FALSE");

    // Discovery: Who-Is/I-Am (DM-DDB-B) and Who-Has/I-Have (DM-DOB-B). The
    // stack answers both regardless, but Protocol_Services_Supported is
    // emitted verbatim from these bits, so without them the device would
    // misreport its own support.
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

    // --- Add Network Port 1 (BACnet/IP, "BACnet IP") - only with --port ----
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
    // function (NM-SCH-B). A real SC node can connect to g_scHubAcceptUri once
    // certificates exist under --sc-cert-dir. Network_Number 0 with quality
    // "unknown" unless --sc-network-number is given: this device isn't a
    // router, so it has no network number to report of its own.
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
    // doc comment); connectionRole 0 = hub function. The stack refuses a
    // device's Connect-Request beyond g_scMaxHubConnections.
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

    // Interoperability relaxations - off by default (see g_scAcceptDeviceWithoutHello
    // and g_scAcceptHubWithoutHello). Device-wide: the stack applies the flags
    // to every BACnet/SC data link.
    {
        uint8_t compatibilityFlags = 0;
        if (g_scAcceptHubWithoutHello) {
            compatibilityFlags |= SC_COMPATIBILITY_ACCEPT_CONNECT_ACCEPT_WITHOUT_HELLO;
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                "BACnet/SC compatibility: the hub connector accepts a Connect-Accept without the Hello "
                "option (--sc-accept-hub-without-hello). This deviates from ANSI/ASHRAE 135 AB.2.2.");
        }
        if (g_scAcceptDeviceWithoutHello) {
            compatibilityFlags |= SC_COMPATIBILITY_ACCEPT_CONNECT_REQUEST_WITHOUT_HELLO;
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                "BACnet/SC compatibility: the hub accepts a device's Connect-Request without the Hello "
                "option (--sc-accept-device-without-hello), e.g. from YABE. This deviates from ANSI/ASHRAE "
                "135 AB.2.2.");
        }
        if (compatibilityFlags != 0 && !BACnetStack_SetBACnetSCCompatibilityFlags(compatibilityFlags)) {
            printf("Error: Failed to set the BACnet/SC compatibility flags (0x%02x).\n", compatibilityFlags);
            return 1;
        }
    }

    // --- Optionally ALSO configure the hub CONNECTOR (initiator) role -------
    // Off unless --sc-hub-uri was given (see g_scHubUri): the stack rejects an
    // empty primary URI, and a hub does not need a connector to answer the
    // devices connected to it. It exists so this hub can ALSO dial out to
    // another hub (a real one, or a second instance of this example), with an
    // optional failover.
    if (!g_scHubUri.empty()) {
        // The connector's VMAC is not derived by the stack for a hub-function-only
        // port: Network Port 2's MAC_Address stays empty until a connector is
        // configured, and BACnetStack_SetBACnetSCHubConnectorForNetworkPort takes
        // the VMAC explicitly. Compute it the way BACnetStack_SetBACnetSCUuid's
        // doc comment describes: the last 6 octets of the UUID, XORing the final
        // octet with 0x01 if those 6 octets would otherwise be all-zero or all-FF
        // (this is the SAME device/UUID dialing out, not a separate identity).
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

    // --- Add the 4 certificate/CSR File objects ----------------------------
    // and bind them to Network Port 2's SC certificate properties. Content is
    // served from --sc-cert-dir by CallbackReadFile (section 2d) - never the
    // private key. The operational and issuer certificates are writable for the
    // clause 19.8.3 certificate procedures (section 2d-ii); the Certificate
    // Signing Request is read-only.
    if (!BACnetStack_AddFileObject(g_deviceInstance, FILE_OPERATIONAL_CERT_INSTANCE,
                                   /*isWritable*/ true, /*isConfigurationFile*/ false,
                                   FILE_ACCESS_METHOD_STREAM)) {
        printf("Error: Failed to add File %u (Operational Certificate).\n", FILE_OPERATIONAL_CERT_INSTANCE);
        return 1;
    }
    if (!BACnetStack_AddFileObject(g_deviceInstance, FILE_CSR_INSTANCE,
                                   /*isWritable*/ false, /*isConfigurationFile*/ false,
                                   FILE_ACCESS_METHOD_STREAM)) {
        printf("Error: Failed to add File %u (Certificate Signing Request).\n", FILE_CSR_INSTANCE);
        return 1;
    }
    if (!BACnetStack_AddFileObject(g_deviceInstance, FILE_ISSUER_CERT_1_INSTANCE,
                                   /*isWritable*/ true, /*isConfigurationFile*/ false,
                                   FILE_ACCESS_METHOD_STREAM)) {
        printf("Error: Failed to add File %u (Issuer Certificate Slot 1).\n", FILE_ISSUER_CERT_1_INSTANCE);
        return 1;
    }
    if (!BACnetStack_AddFileObject(g_deviceInstance, FILE_ISSUER_CERT_2_INSTANCE,
                                   /*isWritable*/ true, /*isConfigurationFile*/ false,
                                   FILE_ACCESS_METHOD_STREAM)) {
        printf("Error: Failed to add File %u (Issuer Certificate Slot 2).\n", FILE_ISSUER_CERT_2_INSTANCE);
        return 1;
    }
    // Archive is writable on every File object (cl. 12.13, W) - see SetPropertyBool.
    for (const uint32_t fileInstance : {FILE_OPERATIONAL_CERT_INSTANCE, FILE_CSR_INSTANCE,
                                        FILE_ISSUER_CERT_1_INSTANCE, FILE_ISSUER_CERT_2_INSTANCE}) {
        if (!BACnetStack_SetPropertyWritable(g_deviceInstance, OBJECT_TYPE_FILE, fileInstance,
                                             PROPERTY_IDENTIFIER_ARCHIVE, true)) {
            printf("Error: Failed to make Archive writable on File %u.\n", fileInstance);
            return 1;
        }
    }
    {
        // Exactly 2 issuer slots - the stack requires this regardless of how many
        // distinct CAs are in use. Slot 2 serves slot 1's certificate until a
        // client writes its own (see ScCertFilePath).
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

    // The configuration above is this hub's own start-up state, not a change a
    // client asked for. The stack leaves what BACnetStack_SetBACnetSCCertificateFileObjects
    // bound pending (Changes_Pending TRUE until a ReinitializeDevice
    // ACTIVATE_CHANGES), so activate it now: a hub that has just started must
    // report Changes_Pending FALSE (cl. 12.56.100), or a Network Port Command
    // that needs "no changes pending" would be refused on a fresh hub.
    // 4194303 = every Network Port of the device.
    if (!BACnetStack_ActivateNetworkPortPendingChanges(g_deviceInstance, 4194303)) {
        printf("Error: Failed to activate the start-up Network Port configuration.\n");
        return 1;
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
                continue;  // Network Port 1 doesn't exist without --port
            }
            if (!BACnetStack_SetPropertyEnabled(g_deviceInstance, o.type, o.instance,
                                                PROPERTY_IDENTIFIER_DESCRIPTION, true)) {
                printf("Error: Failed to enable Description on object type %u instance %u.\n",
                       (unsigned)o.type, o.instance);
                return 1;
            }
        }
    }

    // Who-Is is answered automatically. With --port the spec also requires a
    // device to announce itself on start-up, so broadcast an unsolicited I-Am
    // now (to the local subnet broadcast - the BACnet/IP Network Port's own
    // network). g_scRouter.SendIAm(), not CASExampleHelper::SendIAm() - the
    // router owns Network Port 1's UDP socket directly. Without --port there is
    // no BACnet/IP network to broadcast it on, and no BACnet/SC device is
    // connected yet - devices find the hub with Who-Is once they connect.
    if (g_bacnetIpEnabled) {
        g_scRouter.SendIAm(g_deviceInstance);
    }

    printf("FYI: BACnet/SC hub function is CONFIGURED on Network Port %u (BACnet SC), accept URI %s, "
           "at most %u devices. Certificates: %s.\n",
           SC_NETWORK_PORT_INSTANCE, g_scHubAcceptUri.c_str(), (unsigned)g_scMaxHubConnections, g_scCertDir.c_str());
    printf("FYI: Device %u (\"%s\") ready. Vendor ID %u. Press 'h' for help.\n",
           g_deviceInstance, g_deviceName.c_str(), VENDOR_IDENTIFIER);

    // --- Run the stack ------------------------------------------------------
    std::string crlFingerprint = FileFingerprint(g_scCrlPath);
    std::chrono::steady_clock::time_point lastCrlCheck = std::chrono::steady_clock::now();
    bool running = true;
    uint64_t refusalsSeen = 0;  // ScTransportMetrics::connectRequestsRefused already looked at
    std::chrono::steady_clock::time_point lastLimitMessage;
    bool limitMessageShown = false;
    while (running) {
        // THE RUN LIMIT (see DEMO_RUN_LIMIT_SECONDS): stop after 24 hours.
        if (std::chrono::steady_clock::now() - g_startTime >= std::chrono::seconds(g_runLimitSeconds)) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning, RUN_LIMIT_MESSAGE_FORMAT,
                                  FormatRunLimit(g_runLimitSeconds).c_str());
            break;
        }

        BACnetStack_Tick();

        // Pump the WebSocket/TLS transport non-blockingly, then report any
        // resulting connection-status changes to the stack. NEVER call
        // BACnetStack_* from inside an lws callback (sc_transport/README.md
        // fact 6) - Service() only queues; DrainStatusEvents() is what actually
        // calls BACnetStack_SetBACnetSCWebSocketStatus, safely here in the main
        // loop.
        g_scTransport.Service();
        g_scRouter.DrainStatusEvents();

        // THE CONNECTION LIMIT (see g_scMaxHubConnections): a device was
        // refused while the hub already had the most devices it accepts. The
        // stack's refusal itself is logged by the transport's audit trail;
        // this says why, at most once a minute.
        {
            const CASSc::ScTransportMetrics metrics = g_scTransport.GetMetrics();
            if (metrics.connectRequestsRefused > refusalsSeen) {
                refusalsSeen = metrics.connectRequestsRefused;
                const auto now = std::chrono::steady_clock::now();
                if (metrics.acceptedPeerCount >= g_scMaxHubConnections &&
                    (!limitMessageShown || now - lastLimitMessage >= std::chrono::minutes(1))) {
                    limitMessageShown = true;
                    lastLimitMessage = now;
                    CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning, CONNECTION_LIMIT_MESSAGE_FORMAT,
                                          (unsigned)g_scMaxHubConnections);
                }
            }
        }

        // A new, changed or removed certificate revocation list: reload TLS so
        // it is used. Restarting the listener drops every device; each
        // reconnects, and one whose certificate is now revoked is refused -
        // which is how an open connection from a revoked device is closed.
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

        // New certificates activated by ReinitializeDevice (section 2d-ii) or
        // a CRL change: rebuild the TLS context so it loads the new files (the
        // trusted-issuer bundle is already refreshed). The stack restarts the
        // SC port by itself only when a File object REFERENCE changed, not the
        // contents, so this is what applies a content-only change. Devices
        // reconnect under the new certificates.
        if (g_scReloadCredentialsRequested) {
            g_scReloadCredentialsRequested = false;
            g_scTransport.ReloadCredentials();
        }

        switch (CASExampleHelper::PollKey()) {
            case CASExampleHelper::KeyCommand::Help:
                CASExampleHelper::PrintHelp(APP_NAME, APP_VERSION);
                printf("  m     - show the BACnet/SC connection and traffic counters\n");
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
                PrintConnectionCounters();
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
    g_scRouter.Shutdown();
    printf("FYI: stopped.\n");
    LogFile::Stop();
    return 0;
}
