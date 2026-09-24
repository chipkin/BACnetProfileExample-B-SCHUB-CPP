# BACnet Protocol Implementation Conformance Statement (PICS)

For the **BACnet B-SCHUB (BACnet/SC Hub) C++ example** -
see [README.md](../README.md).

> This is the PICS **for the example as shipped**. It describes a tutorial
> device announcing itself as a Chipkin demo, not a product. When you turn this
> example into your own device, this document is one of the things you rewrite:
> the vendor, model and version rows all come from the
> `CHANGE ALL OF THIS BEFORE YOU SHIP` block at the top of `main.cpp`. The
> example has **not** been submitted for BTL certification.

## 1. Product description

| | |
|---|---|
| **Vendor Name** | Chipkin Automation Systems |
| **Vendor Identifier** | 389 |
| **Product Name** | CAS BACnet Stack Example - B-SCHUB |
| **Product Model Number** | CAS BACnet Stack Example - B-SCHUB |
| **Application Software Version** | 1.0.0 |
| **Firmware Revision** | 1.0.0 |
| **BACnet Protocol Version** | 1 |
| **BACnet Protocol Revision** | 24 |

**Product Description:** a BACnet/IP device that answers ReadProperty for three
read-only sensor objects, is discoverable by Who-Is / I-Am and Who-Has / I-Have,
responds to DeviceCommunicationControl, and configures (but does not, in this
build, complete the transport for) a BACnet/SC hub function on a second Network
Port. It is a tutorial for implementers of the B-SCHUB profile, and the series'
spike for BACnet/SC.

## 2. BACnet standardized device profile (Annex L)

**B-SCHUB - BACnet Secure Connect Hub.**

This device claims exactly one profile. Because the B-SCHUB requirements are a
superset of B-GENERAL's, a conformant B-SCHUB device also satisfies
**B-GENERAL** (Annex L.8); that is subsumption, not a second claim.

## 3. BIBBs supported (Annex K)

| BIBB | Description | Notes |
|---|---|---|
| DS-RP-B | Data Sharing - ReadProperty - B | |
| DS-RPM-B | Data Sharing - ReadPropertyMultiple - B | reuses the same per-property Get callbacks as DS-RP-B; no additional application code |
| DM-DDB-B | Device Management - Dynamic Device Binding - B | |
| DM-DOB-B | Device Management - Dynamic Object Binding - B | |
| DM-DCC-B | Device Management - DeviceCommunicationControl - B | |
| NM-SCH-B | Network - Secure Connect Hub Function - B | protocol and WebSocket/TLS transport both real and verified against real peers - see §9 and [README.md "BACnet/SC support"](../README.md#bacnetsc-support-read-this-first) |

No other BIBBs are supported. In particular this device does **not** support
DS-WP-B (WriteProperty), DS-COV-B, any alarm and event (AE-*) BIBB,
scheduling (SCHED-*), or trending (T-*).

## 4. Application services supported

| Service | Initiate | Execute |
|---|:---:|:---:|
| ReadProperty | no | **yes** |
| ReadPropertyMultiple | no | **yes** |
| Who-Is | no | **yes** |
| I-Am | **yes** | - |
| Who-Has | no | **yes** |
| I-Have | **yes** | - |
| DeviceCommunicationControl | no | **yes** |

An unsolicited I-Am is broadcast to the local subnet at start-up, as well as in
response to Who-Is.

Any other confirmed service - including WriteProperty - is rejected. That
rejection is part of the profile boundary, not a limitation to work around.

## 5. Segmentation capability

Segmentation is **not supported** in either direction
(`Segmentation_Supported` = `no-segmentation`). `Max_APDU_Length_Accepted` is
1476 octets, the BACnet/IP maximum.

## 6. Standard object types supported

No object is dynamically creatable or deletable, and no property of any object
is writable.

| Object type | Instance | Object_Name | Optional properties supported |
|---|:---:|---|---|
| Device | 389022 | Chipkin Example B-SCHUB | Description |
| Analog Input | 1 | Bronze | - |
| Binary Input | 1 | Emerald | - |
| Multi-State Input | 1 | Hot Pink | State_Text |
| Network Port | 1 | Vermilion | - |
| Network Port | 2 | Vermilion 2 | - |

The device instance is configurable at run time with `--deviceID` (BACnet
requires the device instance to be configurable).

## 7. Data link layer options

**BACnet/IP (Annex J)**, UDP port 47808 (0xBAC0) by default, configurable at run
time with `--port`. This data link stays active regardless of the BACnet/SC
transport outcome below.

**BACnet/SC (Annex AB)** is configured on Network Port 2 (hub function,
NM-SCH-B) - the SC UUID, hub accept URI and hub function config are all set
and accepted by the stack, and the underlying WebSocket/TLS transport
(mutual TLS 1.3, both the hub-function and hub-connector roles) is real -
see §9.

BBMD is not supported, Foreign Device registration is not supported, and
MS/TP, Ethernet (Annex H) and PTP are not supported.

## 8. Device address binding

Static device binding is **not supported**. The device answers Who-Is/Who-Has
and does not initiate any confirmed request, so it never needs to bind a peer.

## 9. Networking options

Not a router, not a BBMD, and does not register as a foreign device.

**BACnet/SC hub function (NM-SCH-B) - precise status:** the stack-level
configuration is real and stack-verified: `BACnetStack_SetBACnetSCUuid`,
`BACnetStack_AddBACnetSCAcceptUri` and `BACnetStack_SetBACnetSCHubFunctionConfig`
all succeed at start-up. `CallbackSCStartListening`/`CallbackSCStopListening`
and `CallbackInitiateWebsocket`/`CallbackDisconnectWebsocket` forward to a
real libwebsockets + OpenSSL transport (`sc_transport/ScTransport`) - mutual
TLS 1.3, the `hub.bsc.bacnet.org` subprotocol, both the hub-function/listener
role and the (off-by-default) hub-connector/dial-out role. A real BACnet/SC
node can connect to this hub, and this device can dial out to a real
BACnet/SC hub, both verified against real peers. See
[README.md "BACnet/SC support"](../README.md#bacnetsc-support-read-this-first)
and [`../TODO.md`](../TODO.md) for the remaining, genuinely open items
(no hostname checking on the connector, no CRL support).

## 10. Character sets supported

UTF-8 (ANSI X3.4). Supporting a character set does not imply the device can
handle data in all character sets.

## 11. Objects and properties

<!-- OBJECTS-PROPERTIES:BEGIN (generated by tools/gen-objects-properties.py from docs/objects.json - do not edit here) -->
Every object this example creates, and every REQUIRED property of each (per ANSI/ASHRAE 135-2024 clause 12 and the stack's `docs/property-profile-reference.md`), plus the optional properties the example turns on. **Served by** says who answers a ReadProperty: the **stack** generates it, or the **app** serves it from a `GetProperty*` callback in `main.cpp`. A ⚠ row is a required property the app does not serve and the stack would fill with a default - that is a defect, not a feature.

### Device 389022 "Chipkin Example B-SCHUB" - vendor 389 (Chipkin Automation Systems); instance configurable with --deviceID. The stack rows are device-wide facts only the stack knows - the protocol version and revision it implements, the services and object types it was configured with, the live object list and address-binding table. The accepted rows are the stack's configured defaults for APDU limits, segmentation, system status and database revision; an application that answered them from its own constants could contradict the stack, so this example does not

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| System_Status | BACnetDeviceStatus | stack default, accepted (Generic Enumerated default: `0`) | no |
| Vendor_Name | CharacterString | app | no |
| Vendor_Identifier | Unsigned16 | app | no |
| Model_Name | CharacterString | app | no |
| Firmware_Revision | CharacterString | app | no |
| Application_Software_Version | CharacterString | app | no |
| Description *(optional, enabled)* | CharacterString | app | no |
| Protocol_Version | Unsigned | stack | no |
| Protocol_Revision | Unsigned | stack | no |
| Protocol_Services_Supported | BACnetServicesSupported | stack | no |
| Protocol_Object_Types_Supported | BACnetObjectTypesSupported | stack | no |
| Object_List | BACnetARRAY[N] of BACnetObjectIdentifier | stack | no |
| Max_APDU_Length_Accepted | Unsigned | stack default, accepted (`CAS_BACNET_DEVICE_DEFAULT_MAX_APDU_LENGTH_ACCEPTED`) | no |
| Segmentation_Supported | BACnetSegmentation | stack default, accepted (`BACnetSegmentation::noSegmentation`) | no |
| APDU_Timeout | Unsigned | stack default, accepted (`CAS_BACNET_DEVICE_DEFAULT_APDU_TIMEOUT`) | no |
| Number_Of_APDU_Retries | Unsigned | stack default, accepted (`CAS_BACNET_DEVICE_DEFAULT_NUMBER_OF_APDU_RETRIES`) | no |
| Device_Address_Binding | BACnetLIST of BACnetAddressBinding | stack | no |
| Database_Revision | Unsigned | stack default, accepted (Generic UnsignedInteger default: `0`) | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### Analog Input 1 "Bronze" - REAL, degrees Celsius; starts at 21.5; read-only

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Present_Value | Real | app | no |
| Status_Flags | BACnetStatusFlags | stack | no |
| Event_State | BACnetEventState | stack default, accepted (Generic Enumerated default: `0`) | no |
| Out_Of_Service | Boolean | app | no |
| Units | BACnetEngineeringUnits | app | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### Binary Input 1 "Emerald" - starts inactive; read-only

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Present_Value | BACnetBinaryPV | app | no |
| Status_Flags | BACnetStatusFlags | stack | no |
| Event_State | BACnetEventState | stack default, accepted (Generic Enumerated default: `0`) | no |
| Out_Of_Service | Boolean | app | no |
| Polarity | BACnetPolarity | app | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### Multi-state Input 1 "Hot Pink" - state 1 of 3: On, Off, Auto; read-only

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Present_Value | Unsigned | app | no |
| Status_Flags | BACnetStatusFlags | stack | no |
| Event_State | BACnetEventState | stack default, accepted (Generic Enumerated default: `0`) | no |
| Out_Of_Service | Boolean | app | no |
| Number_Of_States | Unsigned | app | no |
| State_Text *(optional, enabled)* | BACnetARRAY[N] of CharacterString | app | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### Network Port 1 "BACnet IP" - BACnet/IP; kept active throughout so this example stays discoverable over plain BACnet/IP regardless of the BACnet/SC transport outcome below. Network_Type and Protocol_Level are set from BACnetStack_AddNetworkPortObject()'s arguments (IPv4, BACnet Application) at start-up, not a GetProperty callback like the object's other app-served rows; Changes_Pending is likewise computed and answered natively by the stack's Network Port object. Reliability has no fault condition this example detects, so it is accepted at the generic default (normal)

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Status_Flags | BACnetStatusFlags | stack | no |
| Reliability | BACnetReliability | stack default, accepted (Generic Enumerated default: `0`) | no |
| Out_Of_Service | Boolean | app | no |
| Network_Type | BACnetNetworkType | app | no |
| Protocol_Level | BACnetProtocolLevel | app | no |
| Changes_Pending | Boolean | app | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### Network Port 2 "BACnet SC" - BACnet/SC (Network_Type = secureConnect(11)); hosts the NM-SCH-B hub function - see README "BACnet/SC support". Both the protocol configuration (UUID, accept URI, SetBACnetSCHubFunctionConfig) and the WebSocket/TLS transport underneath it (sc_transport/ScTransport) are real and verified against real BACnet/SC peers - both the hub-function/listener and hub-connector roles. Network_Type/Protocol_Level are set from BACnetStack_AddNetworkPortObject()'s arguments at start-up, same as Network Port 1. Reliability is accepted at the generic default (normal) for the same reason as Network Port 1

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Status_Flags | BACnetStatusFlags | stack | no |
| Reliability | BACnetReliability | stack default, accepted (Generic Enumerated default: `0`) | no |
| Out_Of_Service | Boolean | app | no |
| Network_Type | BACnetNetworkType | app | no |
| Protocol_Level | BACnetProtocolLevel | app | no |
| Changes_Pending | Boolean | app | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### File 1 "Operational Certificate" - read-only; serves the hub's operational certificate (certs/hub.crt) via AtomicReadFile (stream access) - bound to Network Port 2's Operational_Certificate_File. File_Size/Modification_Date are the real on-disk size/mtime of that file, so they always agree with what AtomicReadFile actually returns. Never certs/hub.key - see main.cpp section 2d

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| File_Type | CharacterString | app | no |
| File_Size | Unsigned | app | no |
| Modification_Date | BACnetDateTime | app | no |
| Archive | Boolean | app | no |
| Read_Only | Boolean | app | no |
| File_Access_Method | BACnetFileAccessMethod | stack | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### File 2 "CSR" - read-only; serves the hub's certificate signing request (certs/hub.csr) - bound to Network Port 2's Certificate_Signing_Request_File. Same file-serving mechanism as File 1

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| File_Type | CharacterString | app | no |
| File_Size | Unsigned | app | no |
| Modification_Date | BACnetDateTime | app | no |
| Archive | Boolean | app | no |
| Read_Only | Boolean | app | no |
| File_Access_Method | BACnetFileAccessMethod | stack | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### File 3 "Issuer Certificate Slot 1" - read-only; issuer certificate slot 1 (certs/ca.crt) - one of Network Port 2's 2 Issuer_Certificate_Files entries (the stack requires exactly 2 slots)

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| File_Type | CharacterString | app | no |
| File_Size | Unsigned | app | no |
| Modification_Date | BACnetDateTime | app | no |
| Archive | Boolean | app | no |
| Read_Only | Boolean | app | no |
| File_Access_Method | BACnetFileAccessMethod | stack | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### File 4 "Issuer Certificate Slot 2" - read-only; issuer certificate slot 2 - also certs/ca.crt (same file as File 3): this lab setup has one CA, and the stack requires exactly 2 issuer slots regardless of how many distinct CAs exist

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| File_Type | CharacterString | app | no |
| File_Size | Unsigned | app | no |
| Modification_Date | BACnetDateTime | app | no |
| Archive | Boolean | app | no |
| Read_Only | Boolean | app | no |
| File_Access_Method | BACnetFileAccessMethod | stack | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

<!-- OBJECTS-PROPERTIES:END -->

## 12. References

- ANSI/ASHRAE Standard 135-2024, Annex A (PICS template), Annex K (BIBBs),
  Annex L (device profiles), Annex AB (BACnet/SC), Clause 12 (object types).
- [README.md](../README.md) - what this example is and how to build it.
- [TUTORIAL.md](../TUTORIAL.md) - how to extend it, and how to keep this
  document honest when you do.
