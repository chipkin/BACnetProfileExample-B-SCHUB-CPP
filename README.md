> [!WARNING]
> **This is an example** of using the CAS BACnet Stack to build a B-SCHUB (BACnet/SC hub) profile. It is for evaluation and testing only.
> **Looking for a production-ready BACnet/SC hub?** See the Chipkin BACnet SC Hub: Contact Chipkin sales@chipkin.com

# BACnet B-SCHUB (BACnet/SC Hub) - C++ example

A minimal example showing how to implement the BACnet **B-SCHUB (BACnet
Secure Connect Hub)** device profile in C++ with the
[CAS BACnet Stack](https://store.chipkin.com/services/stacks/bacnet-stack).
BACnet/SC devices connect to it over TLS 1.3 WebSockets with mutual
certificate authentication, and it relays their BACnet traffic - the way a
BACnet/IP broadcast domain does for UDP devices. It has **no BACnet/IP port**:
the hub's own device is reachable only over BACnet/SC, through the hub.

It is reduced to what the B-SCHUB profile requires: the hub function, the
objects and services the profile needs, and the BACnet/SC certificate
procedures. It accepts **at most 4 BACnet/SC devices** and **stops after 24
hours** (restart it to continue).

**[Download a prebuilt binary](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases)**
(Windows and Linux x64) - or build it yourself if you have a CAS BACnet Stack
licence, see [Build](#build).

- **[TUTORIAL.md](TUTORIAL.md)** - how the code works, and how to review it
  for conformance.
- **[docs/PICS.md](docs/PICS.md)** - the Protocol Implementation Conformance
  Statement: every object, every property, and who answers it.

> **Versions:** this document describes **example v1.7.0**, built and verified
> against **CAS BACnet Stack 6.0.23** (`6.x` @ `e6de4ffd`), at
> **Protocol_Revision 30**, with the vendored `common/` helper at **v3.0.0**.
> Running the example prints all three - if what it prints disagrees with this
> line, trust the program and check `CHANGELOG.md`.

## What is the B-SCHUB (BACnet/SC Hub) profile?

**B-SCHUB**, defined in Annex L of ANSI/ASHRAE 135, is a device that hosts a
**BACnet Secure Connect hub function** (BIBB NM-SCH-B). BACnet/SC (Annex AB)
carries BACnet over TLS-secured WebSockets; nodes connect to a hub, and the hub
relays unicast and broadcast messages between them. Every device on a
BACnet/SC network authenticates with a certificate from the site's
Certificate Authority.

A B-SCHUB device is still a full BACnet device: it has a Device object, a
Network Port object, and answers ReadProperty, ReadPropertyMultiple,
Who-Is/Who-Has and DeviceCommunicationControl - here over BACnet/SC: a device
connected to the hub sends its requests through the hub function.

## The device this example creates

```
Device 389022  "Chipkin Example B-SCHUB"   (Vendor 389 - Chipkin Automation Systems)
    │
    ├── Analog Input 1   "Bronze"                       Present_Value 21.5 (REAL, degrees Celsius)
    ├── Network Port 2   "BACnet SC"                    the BACnet/SC port: the hub function (wss://...:4443/)
    ├── File 1           "Operational Certificate"      the hub's certificate (writable, clause 19.8.3)
    ├── File 2           "Certificate Signing Request"  the hub's CSR (read-only)
    ├── File 3           "Issuer Certificate Slot 1"    a CA the hub trusts (writable)
    └── File 4           "Issuer Certificate Slot 2"    a second CA (writable)
```

The Network Port and File objects are named for what they are rather than
with a colour, so it is obvious which port is the SC one and which File is
the CSR. There is no Network Port 1: the BACnet/SC port keeps instance 2, the
port the CARI certificate tree names (`cert1/device-<n>/port-2/`).

## What this example supports

### BIBBs (BACnet Interoperability Building Blocks)

| BIBB | Description | Supported |
|------|-------------|:---------:|
| DS-RP-B | Data Sharing - ReadProperty - B | ✅ |
| DS-RPM-B | Data Sharing - ReadPropertyMultiple - B | ✅ |
| DM-DDB-B | Device Management - Dynamic Device Binding - B | ✅ |
| DM-DOB-B | Device Management - Dynamic Object Binding - B | ✅ |
| DM-DCC-B | Device Management - DeviceCommunicationControl - B | ✅ (no password) |
| NM-SCH-B | Network Management - BACnet/SC Hub Function - B | ✅ (at most 4 devices) |

### Services (executed / B-side)

| Service | Notes |
|---------|-------|
| ReadProperty, ReadPropertyMultiple | Every property of every object (DS-RP-B, DS-RPM-B). Segmented in both directions. |
| Who-Is / I-Am, Who-Has / I-Have | Discovery, through the hub (DM-DDB-B, DM-DOB-B). No I-Am at start-up: no device is connected yet. |
| DeviceCommunicationControl | DM-DCC-B. |
| AtomicReadFile | The four certificate File objects (never the private key). |
| WriteProperty, AtomicWriteFile, ReinitializeDevice | Only for the BACnet/SC certificate procedures (clause 19.8.3): `File_Size` and AtomicWriteFile into Files 1, 3 and 4, applied by ReinitializeDevice `ACTIVATE_CHANGES`. |
| Network Port `Command` | `DISCARD_CHANGES` and `GENERATE_CSR_FILE` (a new key pair and CSR for the hub). |

### Objects and properties

<!-- OBJECTS-PROPERTIES:BEGIN (generated by tools/gen-objects-properties.py from docs/objects.json - do not edit here) -->
Every object this example creates, and every REQUIRED property of each (per ANSI/ASHRAE 135-2024 clause 12 and the stack's `docs/property-profile-reference.md`), plus the optional properties the example turns on. **Served by** says who answers a ReadProperty: the **stack** generates it, or the **app** serves it from a `GetProperty*` callback in `main.cpp`. A ⚠ row is a required property the app does not serve and the stack would fill with a default - that is a defect, not a feature.

### Device 389022 "Chipkin Example B-SCHUB" - vendor 389 (Chipkin Automation Systems); the series' device instance for B-SCHUB. The stack rows are device-wide facts only the stack knows - the protocol version and revision it implements, the services and object types it was configured with, the live object list and address-binding table. The accepted rows are the stack's configured defaults for APDU limits, segmentation, system status and database revision; an application that answered them from its own constants could contradict the stack, so the example does not. Segmentation_Supported is segmented-both, the CAS BACnet Stack's segmentation configuration (6.x default, cas-bacnet-stack#2992); with it the stack also serves Max_Segments_Accepted (16) and APDU_Segment_Timeout (5000 ms) - see section 5

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
| Segmentation_Supported | BACnetSegmentation | stack | no |
| APDU_Timeout | Unsigned | stack default, accepted (`CAS_BACNET_DEVICE_DEFAULT_APDU_TIMEOUT`) | no |
| Number_Of_APDU_Retries | Unsigned | stack default, accepted (`CAS_BACNET_DEVICE_DEFAULT_NUMBER_OF_APDU_RETRIES`) | no |
| Device_Address_Binding | BACnetLIST of BACnetAddressBinding | stack | no |
| Database_Revision | Unsigned | stack default, accepted (Generic UnsignedInteger default: `0`) | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### Analog Input 1 "Bronze" - REAL, degrees Celsius; starts at 21.5; read-only (a sample value, changed with the arrow keys)

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Present_Value | Real | app | no |
| Description *(optional, enabled)* | CharacterString | app | no |
| Status_Flags | BACnetStatusFlags | stack | no |
| Event_State | BACnetEventState | stack default, accepted (Generic Enumerated default: `0`) | no |
| Out_Of_Service | Boolean | app | no |
| Units | BACnetEngineeringUnits | app | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### Network Port 2 "BACnet SC" - BACnet/SC (Network_Type = secureConnect(11)); the device's only Network Port - there is no BACnet/IP port, so the device is reachable only over BACnet/SC. Hosts the NM-SCH-B hub function (listener, at most 4 devices); the WebSocket/TLS transport is sc_transport/ScTransport. Network_Type and Protocol_Level are set from BACnetStack_AddNetworkPortObject()'s arguments at start-up, not a GetProperty callback like the object's other app-served rows; Changes_Pending is likewise computed and answered natively by the stack's Network Port object. Reliability has no fault condition the hub detects, so it is accepted at the generic default (normal). Network_Number is 0 with Network_Number_Quality unknown; the device is not a router. Command (cl. 12.56.16) is writable: DISCARD_CHANGES also drops staged certificate writes, and GENERATE_CSR_FILE makes a new key pair and Certificate Signing Request (File 2) - the NetworkPortCommand callback in main.cpp

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Description *(optional, enabled)* | CharacterString | app | no |
| Status_Flags | BACnetStatusFlags | stack | no |
| Reliability | BACnetReliability | stack default, accepted (Generic Enumerated default: `0`) | no |
| Out_Of_Service | Boolean | app | no |
| Network_Type | BACnetNetworkType | app | no |
| Protocol_Level | BACnetProtocolLevel | app | no |
| Changes_Pending | Boolean | app | no |
| Command *(optional, enabled)* | BACnetNetworkPortCommand | stack default (Generic Enumerated default: `0`) | yes |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### File 1 "Operational Certificate" - writable over BACnet (clause 19.8.3): File_Size and AtomicWriteFile, staged until ReinitializeDevice ACTIVATE_CHANGES/WARMSTART, which validates the set (parses, matches the hub's private key, chains to an issuer) before writing opr-hub.pem and reloading TLS. Serves the hub's operational certificate via AtomicReadFile (stream access) - bound to Network Port 2's Operational_Certificate_File. File_Size/Modification_Date come from the staged copy or the file on disk

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Description *(optional, enabled)* | CharacterString | app | no |
| File_Type | CharacterString | app | no |
| File_Size | Unsigned | app | yes |
| Modification_Date | BACnetDateTime | app | no |
| Archive | Boolean | app | no |
| Read_Only | Boolean | app | no |
| File_Access_Method | BACnetFileAccessMethod | stack | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### File 2 "Certificate Signing Request" - read-only; serves the hub's certificate signing request (CARI cert1/device-<n>/port-2/csr-hub.pem) - bound to Network Port 2's Certificate_Signing_Request_File. rewritten by the hub on Network Port 2 Command GENERATE_CSR_FILE, for a new key that replaces the hub's key when a certificate signed for it is activated

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Description *(optional, enabled)* | CharacterString | app | no |
| File_Type | CharacterString | app | no |
| File_Size | Unsigned | app | no |
| Modification_Date | BACnetDateTime | app | no |
| Archive | Boolean | app | no |
| Read_Only | Boolean | app | no |
| File_Access_Method | BACnetFileAccessMethod | stack | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### File 3 "Issuer Certificate Slot 1" - writable over BACnet (clause 19.8.3), same staging as File 1; issuer certificate slot 1 (CARI cert1/issuer/iss-1.pem) - one of Network Port 2's 2 Issuer_Certificate_Files entries

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Description *(optional, enabled)* | CharacterString | app | no |
| File_Type | CharacterString | app | no |
| File_Size | Unsigned | app | yes |
| Modification_Date | BACnetDateTime | app | no |
| Archive | Boolean | app | no |
| Read_Only | Boolean | app | no |
| File_Access_Method | BACnetFileAccessMethod | stack | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

### File 4 "Issuer Certificate Slot 2" - writable over BACnet (clause 19.8.3), same staging as File 1; issuer certificate slot 2 (CARI cert1/issuer/iss-2.pem once written; until then it serves slot 1's certificate). TLS trusts every issuer in both slots (trusted-issuers.pem)

| Property | Datatype | Served by | Writable |
|---|---|---|:---:|
| Object_Identifier | BACnetObjectIdentifier | stack | no |
| Object_Name | CharacterString | app | no |
| Object_Type | BACnetObjectType | stack | no |
| Description *(optional, enabled)* | CharacterString | app | no |
| File_Type | CharacterString | app | no |
| File_Size | Unsigned | app | yes |
| Modification_Date | BACnetDateTime | app | no |
| Archive | Boolean | app | no |
| Read_Only | Boolean | app | no |
| File_Access_Method | BACnetFileAccessMethod | stack | no |
| Property_List | BACnetARRAY[N] of BACnetPropertyIdentifier | stack | no |

<!-- OBJECTS-PROPERTIES:END -->

[docs/PICS.md](docs/PICS.md) has the same table plus the data link,
segmentation and networking details.

## Requires the CAS BACnet Stack (licensed product)

This example **builds against the CAS BACnet Stack, which is a commercial
Chipkin product** - it is not free or open source, and there is no public or
trial build. The stack is the **private** git submodule
`submodules/cas-bacnet-stack`, so **the public can't build this example**:
you can fetch and build it once you have a CAS BACnet Stack licence and access
to that repository. To get one, contact Chipkin:
<https://store.chipkin.com/services/stacks/bacnet-stack>.

You do not need a licence to *read* the code, or to run a
[prebuilt release](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases).

## Download

Each [release](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases)
has a Windows `.zip` and a Linux `.tar.gz`, each holding the executable, the
demo certificates (`certs/`), this README, the licence, the third-party
notices and the PICS, plus `SHA256SUMS.txt` to check the downloads
(`sha256sum -c SHA256SUMS.txt`, or `Get-FileHash` on Windows). The Windows
executable is code-signed by Chipkin.

When it starts, the program says what it is: an example, for evaluation and
testing only, that accepts at most 4 BACnet/SC devices and stops after 24
hours. For production use, use the Chipkin BACnet SC Hub - Contact Chipkin
sales@chipkin.com.

## Quick start (the demo certificates)

The repository and every release include a **demo certificate set** in
`certs/`, so the example runs out of the box:

```bash
# Linux
./BACnetExampleBSCHUB

# Windows
.\BACnetExampleBSCHUB.exe
```

(From a source build the program is `build/BACnetExampleBSCHUB` or
`build\Release\BACnetExampleBSCHUB.exe`; run it from the repository folder so
it finds `./certs`.)

Expected output:

```
BACnet B-SCHUB (BACnet/SC Hub) Example - C++ v1.7.0
CAS BACnet Stack version: 6.0.23.0
Common helper (common/) version: 3.0.0

================================================================================
This is an example of using the CAS BACnet Stack to build a BACnet/SC hub (B-SCHUB profile). It is for evaluation and testing only, not for production. It accepts at most 4 BACnet/SC devices and stops after 24 hours. For a production-ready BACnet/SC hub, the Chipkin BACnet SC Hub: Contact Chipkin sales@chipkin.com
================================================================================

2026-10-08 05:28:16 [INFO] log file: "/home/me/BACnetExampleBSCHUB/logs/B-SCHUB.log" (a copy of this console output, emptied at each start-up)
2026-10-08 05:28:16 [INFO] certificates: CARI tree in "./certs", hub port folder cert1/device-389022/port-2
2026-10-08 05:28:16 [INFO] certificate request: created "/home/me/BACnetExampleBSCHUB/certs/hub-cari-request.zip" - send it to your Certificate Authority, then install its response with --import-cari
FYI: BACnet/SC hub function is CONFIGURED on Network Port 2 (BACnet SC), accept URI wss://0.0.0.0:4443/, at most 4 devices. Certificates: ./certs.
FYI: Device 389022 ("Chipkin Example B-SCHUB") ready. Vendor ID 389. Press 'h' for help.
...
BACnet/SC: listening for WebSocket/TLS connections on wss://0.0.0.0:4443/ (subprotocol "hub.bsc.bacnet.org", TLS 1.3, mutual auth)
```

Then connect a BACnet/SC device to `wss://<this computer>:4443/` with one of
the demo device certificates, `certs/clients/client-01-cari.zip` ...
`client-03-cari.zip` (each zip holds the device's certificate, its private key
and the issuer, with a note on how to install them), and talk to the hub's own
device (389022) through the hub. Allow TCP 4443 through your firewall - it is
the only port the example opens.

> **The demo certificates are public, not secret.** Every private key in
> `certs/`, including the CA's, is published with this example, so anyone can
> make a certificate this hub trusts. Use them only for testing on an isolated
> network - see [certs/README.md](certs/README.md).

A fifth BACnet/SC device is refused (the hub logs why); the first four keep
working. After 24 hours the example stops by itself (exit code 0, saying why);
start it again to continue.

### Files it writes

| File | What it is |
|------|------------|
| `logs/B-SCHUB.log` | A copy of everything shown on the console - the example's own lines, the CAS BACnet Stack's and libwebsockets' - in the folder the example runs in (`logs/` is made if missing). **Emptied at each start-up**, never rotated. Its full path is printed at start-up; send it to support with a question. |
| `<sc-cert-dir>/hub-cari-request.zip` | The hub's certificate request, for a Certificate Authority (see [Certificates](#certificates)). Made at start-up if it doesn't exist; never overwritten. |

### Interactive commands

| Key | Action |
|-----|--------|
| `h` | Show the version information and the command list. |
| `q` | Quit. |
| up arrow / down arrow | Increase / decrease Analog Input 1 (`Bronze`) by 1.1. |
| `m` | Show the BACnet/SC counters: connected devices, connects, refusals, traffic. |

## Command line

| Option | Default | Meaning |
|--------|---------|---------|
| `--sc-cert-dir <dir>` | `./certs` | The certificate folder (a CARI tree - see [Certificates](#certificates)). |
| `--deviceID <n>` | `389022` | Device instance; give each device on a BACnet network a unique one. |
| `--sc-port <n>` | `4443` | BACnet/SC (WebSocket/TLS) port devices connect to. |
| `--sc-accept-device-without-hello [on\|off]` | off | Accept a device whose Connect-Request leaves out the Hello option ANSI/ASHRAE 135 AB.2.2 requires. YABE needs it - see [Testing with YABE](#testing-with-yabe). |
| `--import-cari <zip>` | - | Install a CA's CARI response (the hub's certificate and issuers) in the certificate folder; then exit. |
| `--help`, `-h` | - | Show usage and exit. |
| `--version` | - | Print the example, stack and `common/` versions, then exit. |

Any other option is refused. The connection limit (4 BACnet/SC devices) and
the run limit (24 hours) are fixed. `--help` also names the files the example
writes and links to this repository.

**For automated tests only**, the environment variable
`BSCHUB_TEST_RUN_LIMIT_SECONDS=<n>` shortens the run limit to `n` seconds (1
to 86400; it can't raise it), so a test can watch the example stop. The
start-up says when it is set. It is deliberately not a command-line option.

## Certificates

The hub reads its certificates from `--sc-cert-dir` in the **CARI** format
(Certificate Authority Requirements Interchange, ANSI/ASHRAE 135-2024 Annex
AA.2):

```
cert1/device-389022/port-2/hub/          marks Network Port 2 as a hub function
cert1/device-389022/port-2/opr-hub.pem   the hub's certificate     (File 1)
cert1/device-389022/port-2/key-hub.pem   the hub's private key     (no File object)
cert1/device-389022/port-2/csr-hub.pem   the hub's request         (File 2)
cert1/issuer/iss-1.pem, iss-2.pem        the CAs the hub trusts    (Files 3, 4)
issuer-crl.pem                           optional revocation list(s) from the CA
```

**The hub never signs certificates.** A Certificate Authority does - the
Chipkin BACnet SC Certificate Authority, BACnet International's BACCARI, or
your own. To use your own CA:

1. `BACnetExampleBSCHUB --sc-cert-dir site-certs` - at start-up the hub makes
   `site-certs/hub-cari-request.zip` (the request only, never the key) if it
   doesn't exist, and logs its path. With no key yet, it first makes the hub's
   private key and certificate request; **an existing key is never replaced**,
   and an existing zip is never overwritten (delete it to have it made again).
   The hub can't serve BACnet/SC until step 3, so stop it (`q`) once the zip is
   there.
2. Send `hub-cari-request.zip` to the CA. It returns a CARI response zip: the
   hub's certificate and the issuer certificate(s).
3. `BACnetExampleBSCHUB --sc-cert-dir site-certs --import-cari response.zip` -
   checks the certificate is for the hub's request and signed by an issuer in
   the zip, then installs it.
4. `BACnetExampleBSCHUB --sc-cert-dir site-certs` - and give each device its
   own certificate from the same CA.

Certificates can also be replaced over BACnet while the hub runs (clause
19.8.3, e.g. from the CAS BACnet Explorer): write the new certificate into
File 1 (or a new CA into File 3 or 4), then ReinitializeDevice
`ACTIVATE_CHANGES`. The hub checks the set first - it must parse, match the
hub's key and chain to an issuer - so it never locks itself out. A new or
changed `issuer-crl.pem` is picked up within a few seconds.

`tools/make_test_certs.py` makes a throwaway test set (a CA, the hub's tree
and device zips) - it is how the demo set was made, and it is for testing
only.

## Testing with YABE

YABE's BACnet/SC client leaves out the Hello option ANSI/ASHRAE 135 requires
in a Connect-Request, so start the hub with
`--sc-accept-device-without-hello` for it. YABE uses Windows' own TLS, which
makes TLS 1.3 client connections only on Windows 11 / Server 2022 or later;
on Windows 10 use another client (the CAS BACnet Explorer has its own TLS
1.3). Give YABE a device certificate and key from a `certs/clients/*.zip` and
the issuer `cert1/issuer/iss-1.pem`.

## Prerequisites

- A C++17 compiler (MSVC, GCC or Clang), CMake 3.15+, Git.
- [vcpkg](https://vcpkg.io/) with `VCPKG_ROOT` set: it supplies OpenSSL,
  libwebsockets and zlib (`vcpkg.json`). Visual Studio's Developer Command
  Prompt already has it.
- Windows: Visual Studio with "Desktop development with C++".
- Debian/Ubuntu: `sudo apt install build-essential cmake git pkg-config`, plus vcpkg.
- Python 3 for the tests and `tools/make_test_certs.py`
  (`pip install -r tests/sc/requirements.txt`).

## Build

You need a CAS BACnet Stack licence and access to its repository (see above).

```bash
git clone --recursive https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP.git
cd BACnetProfileExample-B-SCHUB-CPP

cmake -B build -S .
cmake --build build --config Release
```

Already cloned without `--recursive`? Run `git submodule update --init --recursive`
first. The first build compiles the CAS BACnet Stack (about 600 files) and,
the first time on a machine, OpenSSL (10-15 minutes); later builds are
incremental. To use a stack outside the submodule:
`cmake -B build -S . -D CAS_STACK_DIR=/path/to/cas-bacnet-stack`.

## Testing

`tests/sc/` holds the verification scripts; see its
[README](tests/sc/README.md). CI runs them on Windows and Linux.

| Script | Checks |
|---|---|
| `hub_listener_test.py` | TLS 1.3 and subprotocol negotiation, refusal of bad clients, Connect-Request/Accept, the Hello option (and `--sc-accept-device-without-hello`). |
| `connection_limit_test.py` | The start-up banner; 4 devices accepted, the 5th refused and logged. |
| `startup_test.py` | `--help` (repository link, the request-file note), `logs/B-SCHUB.log` (everything, emptied at start-up), no BACnet/IP. |
| `run_limit_test.py` | The 24-hour run limit, with the test-only shorter limit. |
| `hub_cert_test.py` | The start-up certificate request (made once, never overwritten, the key never replaced), `--import-cari` and its refusals; removed options refused. |
| `file_object_test.py` | The certificate File objects over BACnet/SC; the private key is never served. |
| `cert_procedure_test.py` | The clause 19.8.3 certificate procedures over BACnet/SC. |
| `rpm_test.py`, `segmentation_test.py` | ReadPropertyMultiple, `Object_List` (one Network Port), and segmentation in both directions - over BACnet/SC. |

The BACnet tests connect to the hub as a BACnet/SC device (`tests/sc/sc_client.py`,
a bacpypes3 application on a hub connection) - there is no BACnet/IP to use.
| `cert_files_test.py` | The device CARI zips `tools/make_test_certs.py` writes. |

## Licensing

- **This example** (everything outside `submodules/`) is public domain under
  [CC0-1.0](LICENSE) - copy it into your own product.
- **CAS BACnet Stack** - a separate, commercial Chipkin product, not covered
  by CC0: <https://store.chipkin.com/services/stacks/bacnet-stack>.
- **libwebsockets** (MIT), **OpenSSL 3** (Apache-2.0) and **zlib** (Zlib), via
  vcpkg - see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Security issues: see [SECURITY.md](SECURITY.md).

## The BACnet profile example series

<!-- PROFILE-TABLE:BEGIN (generated from cas-bacnet-stack-examples/docs/profile-table.md - do not edit here) -->
The CAS BACnet Stack supports every standardized device profile in ASHRAE 135-2024 Annex L, and there is one example repository per profile. Pick the profile your device claims, then the language you build in. "Ask" means the example hasn't been built yet for that language - [contact Chipkin](https://store.chipkin.com/contact-us) if you need one.

### Controllers (Annex L.4)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-SS** Smart Sensor | [B-SS-CPP](https://github.com/chipkin/BACnetProfileExample-B-SS-CPP) | [B-SS-Node](https://github.com/chipkin/BACnetProfileExample-B-SS-Node) | [B-SS-CS](https://github.com/chipkin/BACnetProfileExample-B-SS-CS) | [B-SS-Rust](https://github.com/chipkin/BACnetProfileExample-B-SS-Rust) | [B-SS-Python](https://github.com/chipkin/BACnetProfileExample-B-SS-Python) | [B-SS-Go](https://github.com/chipkin/BACnetProfileExample-B-SS-Go) |
| **B-SA** Smart Actuator | [B-SA-CPP](https://github.com/chipkin/BACnetProfileExample-B-SA-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-ASC** Application Specific Controller | [B-ASC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ASC-CPP) | [B-ASC-Node](https://github.com/chipkin/BACnetProfileExample-B-ASC-Node) | Ask | Ask | Ask | Ask |
| **B-AAC** Advanced Application Controller | [B-AAC-CPP](https://github.com/chipkin/BACnetProfileExample-B-AAC-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-BC** Building Controller | [B-BC-CPP](https://github.com/chipkin/BACnetProfileExample-B-BC-CPP) | Ask | Ask | Ask | Ask | Ask |

### Life safety controllers (Annex L.5)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-LSC** Life Safety Controller | [B-LSC-CPP](https://github.com/chipkin/BACnetProfileExample-B-LSC-CPP) 🚧 | Ask | Ask | Ask | Ask | Ask |
| **B-ALSC** Advanced Life Safety Controller | [B-ALSC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ALSC-CPP) | Ask | Ask | Ask | Ask | Ask |

### Access control controllers (Annex L.6)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-ACC** Access Control Controller | [B-ACC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ACC-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-AACC** Advanced Access Control Controller | [B-AACC-CPP](https://github.com/chipkin/BACnetProfileExample-B-AACC-CPP) | Ask | Ask | Ask | Ask | Ask |

### Lighting controllers (Annex L.11)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-LD** Lighting Device | [B-LD-CPP](https://github.com/chipkin/BACnetProfileExample-B-LD-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-LS** Lighting Supervisor | [B-LS-CPP](https://github.com/chipkin/BACnetProfileExample-B-LS-CPP) | Ask | Ask | Ask | Ask | Ask |

### Elevator controllers (Annex L.13)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-EM** Elevator Monitor | [B-EM-CPP](https://github.com/chipkin/BACnetProfileExample-B-EM-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-EC** Elevator Controller | [B-EC-CPP](https://github.com/chipkin/BACnetProfileExample-B-EC-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-AEC** Advanced Elevator Controller | [B-AEC-CPP](https://github.com/chipkin/BACnetProfileExample-B-AEC-CPP) | Ask | Ask | Ask | Ask | Ask |

### Authentication and authorization (Annex L.14)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-AS** Authorization Server | [B-AS-CPP](https://github.com/chipkin/BACnetProfileExample-B-AS-CPP) | Ask | Ask | Ask | Ask | Ask |

### Miscellaneous (Annex L.7, combinable with any one family)

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-BBMD** Broadcast Management Device | [B-BBMD-CPP](https://github.com/chipkin/BACnetProfileExample-B-BBMD-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-ACDC** Access Control Door Controller | [B-ACDC-CPP](https://github.com/chipkin/BACnetProfileExample-B-ACDC-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-ACCR** Access Control Credential Reader | [B-ACCR-CPP](https://github.com/chipkin/BACnetProfileExample-B-ACCR-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-RTR** Router | [B-RTR-CPP](https://github.com/chipkin/BACnetProfileExample-B-RTR-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-GW** Gateway | [B-GW-CPP](https://github.com/chipkin/BACnetProfileExample-B-GW-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-DAP** Device Address Proxy | [B-DAP-CPP](https://github.com/chipkin/BACnetProfileExample-B-DAP-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-SCHUB** BACnet/SC Hub | [B-SCHUB-CPP](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-GENERAL** General device (Annex L.8) | *(satisfied by every example above)* | — | — | — | — | — |

### Operator interfaces and workstations (Annex L.1–L.3, L.9–L.10, L.12)

Client-side profiles.

| Profile | C++ | Node.js | C# | Rust | Python | Go |
|---|---|---|---|---|---|---|
| **B-OD** Operator Display | [B-OD-CPP](https://github.com/chipkin/BACnetProfileExample-B-OD-CPP) | Ask | Ask | Ask | Ask | Ask |
| **B-OWS** Operator Workstation | planned | — | — | — | — | — |
| **B-AWS** Advanced Operator Workstation | planned | — | — | — | — | — |
| **B-XAWS** Extended Advanced Operator Workstation | planned | — | — | — | — | — |
| **B-LSAP** Life Safety Annunciator Panel | planned | — | — | — | — | — |
| **B-LSWS** Life Safety Workstation | planned | — | — | — | — | — |
| **B-ALSWS** Advanced Life Safety Workstation | planned | — | — | — | — | — |
| **B-ACSD** Access Control Security Display | planned | — | — | — | — | — |
| **B-ACWS** Access Control Workstation | planned | — | — | — | — | — |
| **B-AACWS** Advanced Access Control Workstation | planned | — | — | — | — | — |
| **B-LOD** Lighting Operator Display | planned | — | — | — | — | — |
| **B-ALWS** Advanced Lighting Workstation | planned | — | — | — | — | — |
| **B-LCS** Lighting Control Station | planned | — | — | — | — | — |
| **B-ALCS** Advanced Lighting Control Station | planned | — | — | — | — | — |
| **B-ED** Elevator Display | planned | — | — | — | — | — |
| **B-EWS** Elevator Workstation | planned | — | — | — | — | — |
| **B-AEWS** Advanced Elevator Workstation | planned | — | — | — | — | — |

🚧 = in progress. "Ask" = not yet built for that language; contact Chipkin if you need it. Profile definitions: ANSI/ASHRAE 135-2024 Annex L. BIBB definitions: Annex K. Get the stack: <https://store.chipkin.com/services/stacks/bacnet-stack>.
<!-- PROFILE-TABLE:END -->

## References

- **ANSI/ASHRAE Standard 135** (BACnet): objects (clause 12), services
  (clause 16), certificate management (clause 19.8), BACnet/SC (Annex AB),
  CARI (Annex AA.2), device profiles (Annex L). From the
  [ASHRAE store](https://www.ashrae.org/technical-resources/standards-and-guidelines).
- **CAS BACnet Stack**: <https://store.chipkin.com/services/stacks/bacnet-stack>.
- **CAS BACnet Explorer**: <https://store.chipkin.com/products/tools/cas-bacnet-explorer>.
- **What is BACnet?**: <https://docs.chipkin.com/protocols/bacnet/>.
- **Shared helper used by this example** - [`common/README.md`](common/README.md).

See also [TUTORIAL.md](TUTORIAL.md), [docs/PICS.md](docs/PICS.md),
[CHANGELOG.md](CHANGELOG.md), and [AGENTS.md](AGENTS.md).
