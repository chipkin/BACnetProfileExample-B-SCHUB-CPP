// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
#ifndef CAS_BACNET_STACK_EXAMPLE_CONSTANTS_H
#define CAS_BACNET_STACK_EXAMPLE_CONSTANTS_H

// CASBACnetStackExampleConstants.h
// =============================================================================
// A small, self-contained set of the BACnet enumeration values that the example
// projects need. The CAS BACnet Stack defines the FULL enumerations internally,
// in the stack header noted above each section below. We mirror only the handful
// of values used here so each example is easy to read and copy into a customer
// project - open the referenced stack header to see every available value.
//
// Every value matches the BACnet standard (ANSI/ASHRAE 135) and the CAS BACnet
// Stack enumerations. Add more as your own project needs them.
// =============================================================================

#include <stdint.h>

namespace CASBACnetStackExampleConstants {

// -- BACnet object types (Object_Type enumeration) -------------------------
//    Full list: submodules/cas-bacnet-stack/source/BACnetObjectType.h
static const uint16_t OBJECT_TYPE_ANALOG_INPUT = 0;
static const uint16_t OBJECT_TYPE_ANALOG_OUTPUT = 1;
static const uint16_t OBJECT_TYPE_ANALOG_VALUE = 2;
static const uint16_t OBJECT_TYPE_BINARY_INPUT = 3;
static const uint16_t OBJECT_TYPE_BINARY_OUTPUT = 4;
static const uint16_t OBJECT_TYPE_DEVICE = 8;
static const uint16_t OBJECT_TYPE_MULTI_STATE_INPUT = 13;
static const uint16_t OBJECT_TYPE_MULTI_STATE_OUTPUT = 14;
static const uint16_t OBJECT_TYPE_NOTIFICATION_CLASS = 15;
static const uint16_t OBJECT_TYPE_NETWORK_PORT = 56;

// -- BACnet property identifiers (Property_Identifier enumeration) ----------
//    Full list: submodules/cas-bacnet-stack/source/BACnetPropertyIdentifier.h
static const uint32_t PROPERTY_IDENTIFIER_APPLICATION_SOFTWARE_VERSION = 12;
static const uint32_t PROPERTY_IDENTIFIER_APDU_LENGTH = 399;
static const uint32_t PROPERTY_IDENTIFIER_DESCRIPTION = 28;
static const uint32_t PROPERTY_IDENTIFIER_FIRMWARE_REVISION = 44;
static const uint32_t PROPERTY_IDENTIFIER_LOCAL_DATE = 56;
static const uint32_t PROPERTY_IDENTIFIER_LOCAL_TIME = 57;
static const uint32_t PROPERTY_IDENTIFIER_LOCATION = 58;
static const uint32_t PROPERTY_IDENTIFIER_MODEL_NAME = 70;
static const uint32_t PROPERTY_IDENTIFIER_IP_ADDRESS = 400;
static const uint32_t PROPERTY_IDENTIFIER_IP_DEFAULT_GATEWAY = 401;
static const uint32_t PROPERTY_IDENTIFIER_BACNET_IP_MODE = 408;
static const uint32_t PROPERTY_IDENTIFIER_IP_SUBNET_MASK = 411;
static const uint32_t PROPERTY_IDENTIFIER_BACNET_IP_UDP_PORT = 412;
static const uint32_t PROPERTY_IDENTIFIER_LINK_SPEED = 420;
static const uint32_t PROPERTY_IDENTIFIER_MAC_ADDRESS = 423;
static const uint32_t PROPERTY_IDENTIFIER_NUMBER_OF_STATES = 74;
static const uint32_t PROPERTY_IDENTIFIER_OBJECT_IDENTIFIER = 75;
static const uint32_t PROPERTY_IDENTIFIER_OBJECT_NAME = 77;
static const uint32_t PROPERTY_IDENTIFIER_OBJECT_TYPE = 79;
static const uint32_t PROPERTY_IDENTIFIER_OUT_OF_SERVICE = 81;
static const uint32_t PROPERTY_IDENTIFIER_POLARITY = 84;
static const uint32_t PROPERTY_IDENTIFIER_PRESENT_VALUE = 85;
static const uint32_t PROPERTY_IDENTIFIER_PRIORITY_ARRAY = 87;
static const uint32_t PROPERTY_IDENTIFIER_RELINQUISH_DEFAULT = 104;
static const uint32_t PROPERTY_IDENTIFIER_CURRENT_COMMAND_PRIORITY = 431;
static const uint32_t PROPERTY_IDENTIFIER_REFERENCE_PORT = 483;
static const uint32_t PROPERTY_IDENTIFIER_ROUTING_TABLE = 428; // Network Port; optional, SetPropertyEnabled first
static const uint32_t PROPERTY_IDENTIFIER_STATE_TEXT = 110;
static const uint32_t PROPERTY_IDENTIFIER_STATUS_FLAGS = 111;
static const uint32_t PROPERTY_IDENTIFIER_SYSTEM_STATUS = 112;
static const uint32_t PROPERTY_IDENTIFIER_UNITS = 117;
static const uint32_t PROPERTY_IDENTIFIER_VENDOR_IDENTIFIER = 120;
static const uint32_t PROPERTY_IDENTIFIER_VENDOR_NAME = 121;

// -- BACnet engineering units (Engineering_Units enumeration) ---------------
//    Full list: submodules/cas-bacnet-stack/source/BACnetEngineeringUnits.h
static const uint32_t ENGINEERING_UNITS_DEGREES_CELSIUS = 62;
static const uint32_t ENGINEERING_UNITS_PERCENT = 98;

// -- BACnet polarity (Polarity enumeration, for Binary objects) -------------
//    Full list: submodules/cas-bacnet-stack/source/BACnetPolarity.h
static const uint32_t POLARITY_NORMAL = 0;

// -- BACnet/IP mode (BACnetIPMode enumeration, for the Network Port) ---------
//    Full list: submodules/cas-bacnet-stack/source/BACnetIPMode.h
static const uint32_t BACNET_IP_MODE_NORMAL = 0;

// -- BACnet services (Services_Supported enumeration) -----------------------
//    Full list: submodules/cas-bacnet-stack/source/BACnetServicesSupported.h
//    Used with BACnetStack_SetServiceEnabled() to turn individual services on/off.
//    Enable ONLY the services your profile requires - omitting the rest is the
//    whole point of a profile example.
static const uint32_t SERVICE_ACKNOWLEDGE_ALARM = 0;
static const uint32_t SERVICE_CONFIRMED_EVENT_NOTIFICATION = 2;
static const uint32_t SERVICE_READ_PROPERTY = 12;
static const uint32_t SERVICE_READ_PROPERTY_MULTIPLE = 14;
static const uint32_t SERVICE_WRITE_PROPERTY = 15;
static const uint32_t SERVICE_WRITE_PROPERTY_MULTIPLE = 16;
static const uint32_t SERVICE_DEVICE_COMMUNICATION_CONTROL = 17;
static const uint32_t SERVICE_REINITIALIZE_DEVICE = 20;
static const uint32_t SERVICE_I_AM = 26;
static const uint32_t SERVICE_I_HAVE = 27;
static const uint32_t SERVICE_UNCONFIRMED_EVENT_NOTIFICATION = 29;
static const uint32_t SERVICE_TIME_SYNCHRONIZATION = 32;
static const uint32_t SERVICE_WHO_HAS = 33;
static const uint32_t SERVICE_WHO_IS = 34;
static const uint32_t SERVICE_UTC_TIME_SYNCHRONIZATION = 36;
static const uint32_t SERVICE_GET_EVENT_INFORMATION = 39;

// -- Confirmed-service choice, for the A-side Send* calls -------------------
//    Same numbers as the Services_Supported values above; kept under the names
//    the client-side BACnetStack_Send* helpers use so a client example reads
//    naturally. (READ_PROPERTY_SERVICE_TYPE == SERVICE_READ_PROPERTY == 12.)
static const uint8_t READ_PROPERTY_SERVICE_TYPE = 12;          // ReadProperty
static const uint8_t READ_PROPERTY_MULTIPLE_SERVICE_TYPE = 14; // ReadPropertyMultiple
static const uint8_t WRITE_PROPERTY_SERVICE_TYPE = 15;         // WriteProperty

// -- BACnet application datatype tags ---------------------------------------
//    Full list: submodules/cas-bacnet-stack/source/BACnetStackDatatypes.h
static const uint8_t BACNET_DATATYPE_REAL = 4;

// -- DeviceCommunicationControl enable/disable (DM-DCC-B) -------------------
//    Full list: submodules/cas-bacnet-stack/source/BACnetEnableDisable.h
//    NOTE: at Protocol_Revision >= 20 the plain `disable` (1) is DEPRECATED -
//    the stack answers it service-request-denied. Only `enable` (0) and
//    `disable-initiation` (2) actually take effect.
static const uint8_t DCC_ENABLE = 0;             // resume all communication
static const uint8_t DCC_DISABLE = 1;            // stop initiating AND responding
static const uint8_t DCC_DISABLE_INITIATION = 2; // keep responding, stop initiating

// -- ReinitializeDevice states (DM-RD-B) ------------------------------------
//    Full list: submodules/cas-bacnet-stack/source/BACnetReinitializedStateOfDevice.h
static const uint32_t REINITIALIZE_STATE_COLDSTART = 0;
static const uint32_t REINITIALIZE_STATE_WARMSTART = 1;

// -- Notification type (for alarm/event objects) ----------------------------
//    Full list: submodules/cas-bacnet-stack/source/BACnetNotifyType.h
static const uint8_t NOTIFY_TYPE_ALARM = 0;
static const uint8_t NOTIFY_TYPE_EVENT = 1;

// -- BACnet error codes (Error_Code enumeration) ----------------------------
//    Full list: submodules/cas-bacnet-stack/source/BACnetErrorCode.h
//    A SetProperty* callback writes one of these to its errorCode out-parameter
//    and returns false to reject a write with that BACnet Error-PDU. Since the
//    per-property error work (CAS BACnet Stack issue #974) the GetProperty*
//    callbacks have the same out-parameter and the same contract - see the
//    commentary above the Get callbacks in main.cpp for when to use it.
static const uint32_t ERROR_CODE_READ_ACCESS_DENIED = 27;
static const uint32_t ERROR_CODE_PASSWORD_FAILURE = 26;
static const uint32_t ERROR_CODE_UNKNOWN_PROPERTY = 32;
static const uint32_t ERROR_CODE_VALUE_OUT_OF_RANGE = 37;
static const uint32_t ERROR_CODE_INVALID_ARRAY_INDEX = 42;
static const uint32_t ERROR_CODE_OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED = 45;
// success (84) is what errorCode is PRESET to before a Get/Set callback runs.
// Leaving it at success on a false return means "I decline, but I am not
// naming an error" - see main.cpp.
static const uint32_t ERROR_CODE_SUCCESS = 84;

// -- Transport network type (BACnetPacket::NetworkType, for the send/receive
//    callbacks and SendIAm).
//    Full list: submodules/cas-bacnet-stack/source/BACnetPacket.h
//    NOTE: this is a DIFFERENT enumeration from the Network Port object's
//    network type below (see the GOTCHA in CASBACnetStackDLL.h).
static const uint8_t NETWORK_TYPE_IP = 0;

// -- Network Port object network type (BACnetNetworkType enumeration, used by
//    BACnetStack_AddNetworkPortObject).
//    Full list: submodules/cas-bacnet-stack/source/BACnetNetworkType.h
static const uint8_t NETWORK_PORT_NETWORK_TYPE_IPV4 = 5;

// -- Network Port object protocol level (BACnetProtocolLevel enumeration, used
//    by BACnetStack_AddNetworkPortObjectWithNetworkNumber).
//    Full list: submodules/cas-bacnet-stack/source/BACnetProtocolLevel.h
static const uint8_t NETWORK_PORT_PROTOCOL_LEVEL_BACNET_APPLICATION = 2;
// The lowest protocol layer references this sentinel instead of another port.
static const uint32_t NETWORK_PORT_REFERENCE_PORT_NONE = 4194303;

// -- Network_Number_Quality (BACnetNetworkNumberQuality, cl. 12.56.11). Says how
//    the port learned its Network_Number. A port that has not been told and has
//    not learned one reports "unknown" with Network_Number = 0.
static const uint8_t NETWORK_NUMBER_QUALITY_UNKNOWN = 0;
static const uint8_t NETWORK_NUMBER_QUALITY_LEARNED = 1;
static const uint8_t NETWORK_NUMBER_QUALITY_LEARNED_CONFIGURED = 2;
static const uint8_t NETWORK_NUMBER_QUALITY_CONFIGURED = 3;

// -- Character string encoding (the encoding byte returned by the character-
//    string Get callback). 0 = UTF-8. The BACnet character-set values are
//    defined by ANSI/ASHRAE 135 Clause 20.2.9; see the stack's handling in
//    submodules/cas-bacnet-stack/source/BACnetPrimitiveCharSTRING.h
static const uint8_t CHARACTER_STRING_ENCODING_UTF8 = 0;

} // namespace CASBACnetStackExampleConstants

#endif // CAS_BACNET_STACK_EXAMPLE_CONSTANTS_H
