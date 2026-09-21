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
// colour name (the convention shared across this example series):
//
//     Device 389022                "Rainbow"      (instance configurable with --deviceID)
//     Analog Input  1               "Bronze"       (REAL, degrees Celsius; read-only)
//     Binary Input  1               "Emerald"      (active / inactive; read-only)
//     Multi-State Input 1           "Hot Pink"     (state 1..3; read-only)
//     Network Port 1                "Vermilion"    (the BACnet/IP port - required, kept
//                                                    active so the device stays
//                                                    discoverable over plain BACnet/IP)
//     Network Port 2                "Vermilion 2"  (the BACnet/SC port - hub function)
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
// with sc_transport/ScTransport (libwebsockets + OpenSSL, via vcpkg) and
// sc_transport/ScTransportRouter (the stack<->transport glue) - see those
// headers for the design, and docs/bacnet-sc-transport-plan.md for how the
// vcpkg/CMake wiring and the non-blocking Service() mechanism were settled.
//
// THIS PHASE (2 of the plan) implements the LISTENER (hub-function accept)
// half for real: CallbackSCStartListening/CallbackSCStopListening below are
// thin forwards to ScTransport, and a real BACnet/SC node can connect. The
// CONNECTOR (initiate) half is Phase 3: CallbackInitiateWebsocket/
// CallbackDisconnectWebsocket already forward to ScTransport's Connect()/
// Disconnect(), but those are themselves still stubs inside ScTransport.cpp
// (they log and return false/no-op, honestly, rather than claiming an
// outbound connection this example does not yet make) - see ScTransport.h's
// class-header comment. This hub-only example does not need a connector to
// answer a node's own requests (see plan open risk #8), so that gap does not
// block NM-SCH-B here.
//
// The BACnet/IP Network Port (1, "Vermilion") stays active and fully functional
// throughout, so the example remains discoverable and testable over plain
// BACnet/IP regardless of BACnet/SC.
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
static const char* APP_VERSION = "1.0.0";

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
    "ReadProperty, discovery, DeviceCommunicationControl and a BACnet/SC hub "
    "function Network Port, alongside an always-active BACnet/IP port. The "
    "BACnet/SC WebSocket/TLS transport itself is a documented stub - see "
    "README.md and TODO.md.";

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
static const uint32_t NETWORK_PORT_INSTANCE = 1;       // "Vermilion"
static const uint32_t MAX_APDU_LENGTH = 1476;          // BACnet/IP APDU length

// Network Port 2 - the BACnet/SC port, hosting the hub function (NM-SCH-B).
// BACnetNetworkType::secureConnect = 11 (source/BACnetNetworkType.h). This is a
// LOCAL constant, not added to common/CASBACnetStackExampleConstants.h - that
// file is the series-wide vendored common/ helper (owned by B-SS-CPP; changing
// it is a separate, serialised protocol - see the series runbook §1). A single
// example needing one extra constant does not justify a common/ change.
static const uint8_t NETWORK_PORT_NETWORK_TYPE_SECURE_CONNECT = 11;
static const uint32_t SC_NETWORK_PORT_INSTANCE = 2;     // "Vermilion 2"
static const uint16_t SC_MAX_HUB_CONNECTIONS = 4;       // small, demo-sized limit

// The BACnet/SC hub accept role's WebSocket/TLS listener - CLI-configurable
// (--sc-port, --sc-cert-dir; see ParseSCPortArg/ParseSCCertDirArg below), since
// unlike the stub this replaces, ScTransport actually opens this port.
static uint16_t g_scPort = 47819;
static std::string g_scCertDir = "./certs";
// Built from g_scPort once the CLI has been parsed - see main(). "0.0.0.0"
// binds every interface (ScTransport::StartListening treats that host - or an
// empty one - as "bind all", the same as a NULL lws iface).
static std::string g_scHubAcceptUri;

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
    (void)objectInstance;
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
    return false;
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

    // Object_Name - the colour name for each object.
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
            return ReturnCharacterString("Vermilion", value, valueElementCount, maxElementCount, encodingType);
        }
        if (objectType == OBJECT_TYPE_NETWORK_PORT && objectInstance == SC_NETWORK_PORT_INSTANCE) {
            return ReturnCharacterString("Vermilion 2", value, valueElementCount, maxElementCount, encodingType);
        }
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
// the hub CONNECTOR/initiator role. Forwards to ScTransport::Connect(), which
// is still a STUB in this phase (Phase 3 implements it for real - see
// ScTransport.h's class-header comment); this hub-only example does not need
// a connector to answer a node's own requests (plan open risk #8), so that gap
// does not block NM-SCH-B. Per plan fact 6, this return value is discarded by
// the stack for the hub-connector path - ScTransport::Connect() still returns
// honestly (false) rather than claiming a connection that was not made.
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
                break;
            }
        }
        return 0;
    }
    const uint16_t port = CASExampleHelper::ParsePortArg(argc, argv, 47808);
    g_deviceInstance = CASExampleHelper::ParseDeviceIdArg(argc, argv, g_deviceInstance);
    g_scPort = ParseScPortArg(argc, argv, g_scPort);
    g_scCertDir = ParseScCertDirArg(argc, argv, g_scCertDir);
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
    // DeviceCommunicationControl (DM-DCC-B).
    BACnetStack_RegisterCallbackDeviceCommunicationControl(DeviceCommunicationControl);
    // BACnet/SC transport callbacks (NM-SCH-B) - stubs, see 2c above and TODO.md.
    BACnetStack_RegisterCallbackInitiateWebsocket(CallbackInitiateWebsocket);
    BACnetStack_RegisterCallbackDisconnectWebsocket(CallbackDisconnectWebsocket);
    BACnetStack_RegisterCallbackSCStartListening(CallbackSCStartListening);
    BACnetStack_RegisterCallbackSCStopListening(CallbackSCStopListening);
    BACnetStack_RegisterCallbackBACnetSCStateChange(CallbackBACnetSCStateChange);

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

    // --- Add Network Port 1 (BACnet/IP, "Vermilion") -------------------------
    if (!BACnetStack_AddNetworkPortObject(
            g_deviceInstance, NETWORK_PORT_INSTANCE,
            NETWORK_PORT_NETWORK_TYPE_IPV4,
            NETWORK_PORT_PROTOCOL_LEVEL_BACNET_APPLICATION,
            0,  // networkNumber: not configured
            NETWORK_NUMBER_QUALITY_UNKNOWN,
            NETWORK_PORT_REFERENCE_PORT_NONE)) {
        printf("Error: Failed to add Network Port 1 (Vermilion).\n");
        return 1;
    }

    // --- Add Network Port 2 (BACnet/SC, "Vermilion 2") + configure the hub ---
    // function (NM-SCH-B). The SC protocol/state-machine side is fully real,
    // and (this phase) so is the listener transport (see 2c) - a real SC node
    // can connect to g_scHubAcceptUri once certs exist under --sc-cert-dir.
    if (!BACnetStack_AddNetworkPortObject(
            g_deviceInstance, SC_NETWORK_PORT_INSTANCE,
            NETWORK_PORT_NETWORK_TYPE_SECURE_CONNECT,
            NETWORK_PORT_PROTOCOL_LEVEL_BACNET_APPLICATION,
            0, NETWORK_NUMBER_QUALITY_UNKNOWN,
            NETWORK_PORT_REFERENCE_PORT_NONE)) {
        printf("Error: Failed to add Network Port 2 (Vermilion 2, BACnet/SC).\n");
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
           "(Vermilion 2), accept URI %s. Certificates: %s. See README.md "
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
