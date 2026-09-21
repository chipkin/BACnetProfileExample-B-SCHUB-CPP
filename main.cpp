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
//     Device 389022                "Rainbow"                   (instance configurable with --deviceID)
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
// RegisterCallbackValidateBACnetSCOperationalCertificate and
// RegisterCallbackGenerateBACnetSCCertificateSigningRequest are also
// registered (section 2d) for documentation/completeness only - both have zero
// call sites in this stack build (see that section's comment) - a known,
// documented limitation of the pinned stack build, not a bug in this example;
// see TODO.md.
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
#include "CASBACnetStackExampleConstants.h"
#include "CASBACnetStackAdapter.h" // the CAS BACnet Stack C API (BACnetStack_*); call
                                    // LoadBACnetFunctions() before any BACnetStack_* call -
                                    // see the top of main() below.
#include "sc_transport/ScTransport.h"
#include "sc_transport/ScTransportRouter.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
static const char* APP_VERSION = "1.1.0";

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
// Object_Name "Rainbow" - a spec violation, and a hard BTL failure. In a real
// product Object_Name must be per-unit configurable too: derive it from a serial
// number, DIP switches, a config file, or add a --deviceName argument.
static const char* DEVICE_NAME = "Rainbow";

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
// accepts the command only if it matches. Set to NULL/empty to accept any request
// (no password required). Change this to your device's secret before shipping -
// note it still crosses the wire in plaintext, so this is a guard against
// accidents, not a security boundary.
static const char* DCC_PASSWORD = "";  // "" = no password required

// FIRMWARE_REVISION / APPLICATION_SOFTWARE_VERSION - your real versions. Wire
// them to your build rather than hard-coding a number that will go stale.
static const char* FIRMWARE_REVISION = "1.0.0";
static const char* APPLICATION_SOFTWARE_VERSION = "1.0.0";

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
static const uint16_t SC_MAX_HUB_CONNECTIONS = 4;       // small, demo-sized limit

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
                return ReturnCharacterString(FIRMWARE_REVISION, value, valueElementCount, maxElementCount, encodingType);
            case PROPERTY_IDENTIFIER_APPLICATION_SOFTWARE_VERSION:
                return ReturnCharacterString(APPLICATION_SOFTWARE_VERSION, value, valueElementCount, maxElementCount, encodingType);
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

    const size_t requiredLength = strlen(DCC_PASSWORD);
    if (requiredLength > 0) {
        bool matches = (password != NULL) && (passwordLength == requiredLength);
        if (matches) {
            for (size_t i = 0; i < requiredLength; ++i) {
                if (password[i] != DCC_PASSWORD[i]) {
                    matches = false;
                    break;
                }
            }
        }
        if (!matches) {
            printf("DeviceCommunicationControl: REJECTED (password failure)\n");
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

// Registered for documentation/completeness only (plan fact 10 / stack item S6) -
// NOT WIRED UP in this stack build: BACnetStack_RegisterCallbackValidateBACnetSCOperationalCertificate's
// own doc comment says the stack stores this pointer and never calls it (verified: no
// call site anywhere in submodules/cas-bacnet-stack/source other than the
// registration function itself). Registering it does NOT validate any certificate,
// and does NOT provide any real security control - this device's actual (and only)
// cert policy is the CA-chain check ScTransport's TLS contexts perform (see
// ScTransport.h). This function's body is unreachable in this stack build.
bool CallbackValidateBACnetSCOperationalCertificate(
        const uint32_t deviceInstance, const uint32_t networkPortInstance,
        const uint8_t* operationalCertificateFileData, const uint32_t operationalCertificateFileDataLength,
        const uint8_t* issuerCertificateFile1Data, const uint32_t issuerCertificateFile1DataLength,
        const uint8_t* issuerCertificateFile2Data, const uint32_t issuerCertificateFile2DataLength,
        const CASBACnetTime timestamp, uint32_t* failingPropertyIdentifier,
        char* details, uint32_t* detailsLength, const uint32_t maxDetailsLength) {
    (void)deviceInstance; (void)networkPortInstance;
    (void)operationalCertificateFileData; (void)operationalCertificateFileDataLength;
    (void)issuerCertificateFile1Data; (void)issuerCertificateFile1DataLength;
    (void)issuerCertificateFile2Data; (void)issuerCertificateFile2DataLength;
    (void)timestamp; (void)failingPropertyIdentifier;
    *detailsLength = 0; // unreachable - see this function's own comment above
    (void)details; (void)maxDetailsLength;
    return true;
}

// Registered for documentation/completeness only - same "NOT WIRED UP" situation
// as CallbackValidateBACnetSCOperationalCertificate above (plan fact 10 / stack
// item S6): BACnetStack_RegisterCallbackGenerateBACnetSCCertificateSigningRequest's
// own doc comment says there is no call site, in particular no WriteProperty path
// reaches it. This device does not implement WriteProperty at all (see the file
// header), so even if the stack wired this callback up later, nothing in this
// device would trigger it today. Unreachable in this stack build.
bool CallbackGenerateBACnetSCCertificateSigningRequest(
        const uint32_t deviceInstance, const uint32_t networkPortInstance,
        const uint8_t* activeOperationalCertificateFileData, const uint32_t activeOperationalCertificateFileDataLength,
        uint8_t* generatedCsrFileData, uint32_t* generatedCsrFileDataLength, const uint32_t maxGeneratedCsrFileDataLength,
        char* details, uint32_t* detailsLength, const uint32_t maxDetailsLength) {
    (void)deviceInstance; (void)networkPortInstance;
    (void)activeOperationalCertificateFileData; (void)activeOperationalCertificateFileDataLength;
    (void)generatedCsrFileData; (void)maxGeneratedCsrFileDataLength;
    (void)details; (void)maxDetailsLength;
    *generatedCsrFileDataLength = 0; // unreachable - see this function's own comment above
    *detailsLength = 0;
    return false;
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

int main(int argc, char** argv) {
    // Show printf output immediately, even when stdout is piped to a file.
    setvbuf(stdout, NULL, _IONBF, 0);

    // --- Load the CAS BACnet Stack -------------------------------------------
    if (!LoadBACnetFunctions()) {
        fprintf(stderr, "Error: failed to load the CAS BACnet Stack: %s\n",
                CASBACnetStackAdapter_LastError());
        return 1;
    }

    // --- Command line + version --------------------------------------------
    if (CASExampleHelper::HandleHelpAndVersionArgs(argc, argv, APP_NAME, APP_VERSION)) {
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
                break;
            }
        }
        return 0;
    }
    const uint16_t port = CASExampleHelper::ParsePortArg(argc, argv, 47808);
    g_deviceInstance = CASExampleHelper::ParseDeviceIdArg(argc, argv, g_deviceInstance);
    g_scPort = ParseScPortArg(argc, argv, g_scPort);
    g_scCertDir = ParseScCertDirArg(argc, argv, g_scCertDir);
    g_scHubUri = ParseStringArg(argc, argv, "--sc-hub-uri");
    g_scFailoverUri = ParseStringArg(argc, argv, "--sc-failover-uri");
    CASExampleHelper::PrintVersion(APP_NAME, APP_VERSION);

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
        printf("FYI: could not read a local IPv4 address; Network Port IP_Address "
               "will report 0.0.0.0.\n");
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
    // Registered for documentation/completeness only - NOT WIRED UP in this stack
    // build (no WriteFile registered either: this device stays read-only). See
    // section 2d's comment on each function above.
    BACnetStack_RegisterCallbackValidateBACnetSCOperationalCertificate(CallbackValidateBACnetSCOperationalCertificate);
    BACnetStack_RegisterCallbackGenerateBACnetSCCertificateSigningRequest(CallbackGenerateBACnetSCCertificateSigningRequest);

    // --- Create the device --------------------------------------------------
    if (!BACnetStack_AddDevice(g_deviceInstance)) {
        printf("Error: Failed to add the Device %u.\n", g_deviceInstance);
        return 1;
    }

    // Enable the services this B-SCHUB profile requires: ReadProperty (DS-RP-B)
    // and DeviceCommunicationControl (DM-DCC-B). We deliberately do NOT enable
    // WriteProperty, ReadPropertyMultiple, SubscribeCOV, or any alarm/event
    // service - a BACnet/SC Hub does not require them, so a faithful B-SCHUB
    // example leaves them off.
    if (!BACnetStack_SetServiceEnabled(g_deviceInstance, SERVICE_READ_PROPERTY, true)) {
        printf("Error: Failed to enable the ReadProperty service.\n");
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
        printf("Error: Failed to add the BACnet/SC hub accept URI.\n");
        return 1;
    }
    if (!BACnetStack_SetBACnetSCHubFunctionConfig(g_deviceInstance, SC_NETWORK_PORT_INSTANCE,
                                                  true, SC_MAX_HUB_CONNECTIONS)) {
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
        // Same VMAC-derivation rule BACnetStack_SetBACnetSCUuid's own doc
        // comment describes for the hub-FUNCTION role ("the last 6 octets of
        // the UUID, XORing the final octet with 0x01 if those 6 octets would
        // otherwise be all-zero or all-FF") - reused here because this is the
        // SAME device/UUID dialing out under the SAME identity, not a
        // separate one. BACnetStack_SetBACnetSCHubConnectorForNetworkPort
        // takes the VMAC explicitly (unlike the hub function, which derives
        // its own internally), so this example must compute it itself.
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

    printf("FYI: Device %u (\"%s\") ready. Vendor ID %u. Press 'h' for help.\n",
           g_deviceInstance, DEVICE_NAME, VENDOR_IDENTIFIER);
    printf("FYI: BACnet/SC hub function is CONFIGURED on Network Port %u "
           "(BACnet SC), accept URI %s. Certificates: %s. See README.md "
           "\"BACnet/SC support\" for how to generate lab test certs.\n",
           SC_NETWORK_PORT_INSTANCE, g_scHubAcceptUri.c_str(), g_scCertDir.c_str());

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
    return 0;
}
