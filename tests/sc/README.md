# BACnet/SC tests

Verification scripts for the B-SCHUB example: the BACnet/SC transport
(`sc_transport/`), the hub's certificates, the certificate File objects and
procedures, the connection and run limits, the log file and `--help`. CI runs
all of them on Windows and Linux (see [CI](#ci) below).

The hub has **no BACnet/IP port** unless it is started with `--port`, so every
BACnet test (ReadProperty, AtomicReadFile, the certificate procedures, ...)
talks to it as a BACnet/SC device: `sc_client.py` connects to the hub with a device certificate, sends a
Connect-Request, and runs a bacpypes3 application on that connection
(Encapsulated-NPDU messages through the hub). It finds the hub's own device
with Who-Is and sends its requests to the VMAC the I-Am came from:

```python
from sc_client import ScClient
async with ScClient(port=4443, cert_dir="certs") as client:
    hub = await client.find_device(389022)
    name = await client.app.read_property(hub, ObjectIdentifier("device,389022"), "object-name")
```

```
pip install -r tests/sc/requirements.txt
```

The examples below use `./build/BACnetExampleBSCHUB` (Linux/macOS); on
Windows the program is `build\Release\BACnetExampleBSCHUB.exe` (Visual Studio
generator) or `build\BACnetExampleBSCHUB.exe` (Ninja/NMake).

## Certificates

The hub never makes or signs certificates. The scripts use either the demo
set committed in `certs/` (the hub's default `--sc-cert-dir`) or a fresh set
from `tools/make_test_certs.py`, which plays a throwaway CA:

```
python tools/make_test_certs.py --cert-dir test-certs                 # a test CA, the hub's CARI tree, 3 devices
python tools/make_test_certs.py --cert-dir test-certs --devices 1
python tools/make_test_certs.py --cert-dir test-certs --add-devices 2 # more devices, same CA
python tools/make_test_certs.py --cert-dir test-certs --force         # delete the set and start again
```

It writes the hub's tree (`cert1/device-389022/port-2/{opr,key,csr}-hub.pem`,
`cert1/issuer/iss-1.pem`), the test CA in `ca/`, and one CARI response per
device in `clients/<label>-cari.zip` (`client-01`, `client-02`, ...). Needs the
`cryptography` package. **For testing only.**

`cert_paths.py` finds the hub's and the devices' files for every script, and
unpacks a device's zip into `<cert-dir>/.test-extract/<label>/` when a script
needs its key and certificate (git ignores that folder).

## `hub_listener_test.py` (the hub function / listener)

```
./build/BACnetExampleBSCHUB --sc-port 4443
# in a separate terminal:
python tests/sc/hub_listener_test.py --port 4443 --cert-dir certs
```

Checks:

- **Handshake** - TLS 1.3 negotiates and the server echoes the
  `hub.bsc.bacnet.org` subprotocol; no client certificate, TLS 1.2, a wrong
  subprotocol (HTTP 400) and a text frame (close 1003) are all refused.
- **Connect** - a hand-built BVLC-SC Connect-Request (function 0x06) gets a
  Connect-Accept (0x07) back; a second device with the same VMAC gets a NAK.
- A Connect-Request without the Hello option is refused with a NAK, or, with
  `--expect-no-hello-accepted` against a hub started with
  `--sc-accept-device-without-hello`, accepted (what YABE needs).

`--client-cert <label>` picks which device certificate to connect with
(`clients/<label>-cari.zip`; default `client-01`).

## `connection_limit_test.py` (at most 4 devices)

Starts the executable itself with test certificates and checks:

- the start-up banner says this is an example that accepts at most 4
  BACnet/SC devices and stops after 24 hours, and names the Chipkin BACnet SC
  Hub and sales@chipkin.com, before the `ready` line;
- four devices are accepted; a fifth gets a BVLC-Result NAK, and the hub logs
  the connection-limit warning (naming sales@chipkin.com) once;
- the limit cannot be raised: `--sc-max-hub-connections 5` is refused with the
  example's "at most 4" message (`hub_options_test.py` checks lowering it).

```
python tests/sc/connection_limit_test.py --exe build/BACnetExampleBSCHUB
```

## `run_limit_test.py` (stops after 24 hours)

Starts the executable itself, in a temporary folder. Nobody waits 24 hours,
so it sets the **test-only** environment variable
`BSCHUB_TEST_RUN_LIMIT_SECONDS` (1 to 86400; it can only shorten the limit):

- with `5`, the hub stops by itself after about 5 seconds, exit code 0; the
  banner and the stop message give that limit, and the stop message names the
  Chipkin BACnet SC Hub and "Contact Chipkin sales@chipkin.com"; sales@ appears
  in nothing else;
- `0`, `86401` and `abc` are refused at start-up;
- without the variable the banner says it stops after 24 hours.

```
python tests/sc/run_limit_test.py --exe build/BACnetExampleBSCHUB
```

## `startup_test.py` (`--help`, the log file, BACnet/IP off by default)

Starts the executable itself, in a temporary folder:

- `--help` links to <https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP>,
  says `hub-cari-request.zip` is created at start-up if it doesn't already
  exist, names `logs/B-SCHUB.log`, lists `--port` (the opt-in BACnet/IP port)
  but not `--generate-csr`, and doesn't advertise the product;
- a run writes `logs/B-SCHUB.log` (the folder is made), byte for byte what
  the console showed - including libwebsockets' lines - and prints its full
  path at start-up; a restart empties it first;
- without `--port` nothing in the start-up mentions BACnet/IP or a UDP port;
  with `--port <n>` the start-up (and the log file) says the hub listens on
  UDP port `n`. UDP port 47808 is never touched.

```
python tests/sc/startup_test.py --exe build/BACnetExampleBSCHUB
```

## `ip_port_test.py` (the optional BACnet/IP port)

Starts the executable itself and talks to it over plain BACnet/IP (UDP, hand-built
BVLC/NPDU/APDU; no BACnet library needed). It picks a free UDP port of its own
and never uses 47808.

- **Default:** without `--port` the start-up says nothing about BACnet/IP.
- **`--port <n>`:** the hub says it listens on UDP port `n`; Who-Is gets an I-Am
  from 389022; `Object_List` holds Network Port 1 and 2; Network Port 1 reports
  `BACnet_IP_UDP_Port` = `n` and a 4-octet `IP_Address`; `Network_Number` is 0;
  both Network Ports carry their names; every property in the Device's and the
  Network Ports' `Property_List` reads.
  The BACnet/SC listener still accepts a device.
- **Network numbers:** `--ip-network-number 7 --sc-network-number 9` are the
  ports' `Network_Number`.
- **Options:** a missing, zero, too large or non-numeric `--port`,
  `--ip-network-number` without `--port`, out-of-range numbers and equal
  numbers are refused.

```
python tests/sc/ip_port_test.py --exe build/BACnetExampleBSCHUB
```

## `time_sync_test.py` (TimeSynchronization, DM-TS-B)

Starts the executable itself (with `--port`, on test certificates) and checks that
the Device claims TimeSynchronization, lists
`Local_Date` and `Local_Time`, and that a directed TimeSynchronization sets the
clock: 2031-02-28 and the leap day 2028-02-29 over BACnet/IP (UDP), then
2033-12-31 over BACnet/SC (bacpypes3), each read back with ReadProperty. The
clock keeps running after a synchronization. Requests for 30 February, for 29
February in a common year, with an unspecified hour and with an unspecified
date are ignored (the service is unconfirmed, so there is no reply; the clock
is unchanged).

```
python tests/sc/time_sync_test.py --exe build/BACnetExampleBSCHUB
```

## `utc_time_sync_test.py` (UTCTimeSynchronization, DM-UTC-B)

Starts the executable itself (with `--port`, on test certificates) and checks that
the Device also claims UTCTimeSynchronization, lists `UTC_Offset` and
`Daylight_Savings_Status`, and that both start from the host's time zone (the
standard-time offset in minutes, west of Greenwich positive, and whether daylight
saving time is in effect; the test is run under several `TZ` values to cover
it). Over BACnet/IP both properties are written: `UTC_Offset` takes any multiple
of 15 minutes from -1440 to +1440 (7, 1455, 1500, 2880 and a wrong datatype are
refused and change nothing), and writing either one moves `Local_Time` but not
UTC. A directed UTCTimeSynchronization then sets `Local_Date` / `Local_Time` to
UTC minus `UTC_Offset` (plus one hour while `Daylight_Savings_Status` is TRUE),
across midnight, a year end and a leap day, at the extremes of +-24 h; the clock
keeps running; requests for 30 February, for 29 February in a common year, with an
unspecified hour and with an unspecified date are ignored; a TimeSynchronization
still sets exactly the local time asked for and a UTCTimeSynchronization for the
same moment agrees. Over BACnet/SC a UTCTimeSynchronization sets the clock and
`UTC_Offset` / `Daylight_Savings_Status` read back (bacpypes3).

```
python tests/sc/utc_time_sync_test.py --exe build/BACnetExampleBSCHUB
```

## `hub_options_test.py` (`--device-name`, the connection limit, the rate limits)

- **`--device-name`:** the Device's `Object_Name` (read over `--port`) is the name
  given, the hub's certificate request is for it, and an empty name, a 129-byte
  name or a missing value is refused.
- **`--sc-max-hub-connections 2`:** two devices are accepted, the third gets a
  BVLC-Result NAK and the warning says "at most 2"; 5, 0, -1, `abc`, 70000 and a
  missing value are refused (5 with the example's "at most 4" message).
- **`--sc-rate-limit` / `--sc-rate-limit-total`:** a burst of connection attempts
  past a limit of 2 per address (or 3 in total) is hung up on before the TLS
  handshake and logged; with the defaults (10 and 50) or with 0 (off) a burst is
  not; bad values are refused.

```
python tests/sc/hub_options_test.py --exe build/BACnetExampleBSCHUB
```

## `connector_test.py` (the hub connector, with `fake_hub_server.py`)

Runs `fake_hub_server.py` in-process as a mutual-TLS BACnet/SC hub and starts the
executable against it.

- **Primary hub:** `--sc-hub-uri` is dialled with the hub's own certificate; the
  Connect-Request carries the Hello option; after the Connect-Accept the stack's
  state machine reaches connected; when the fake hub closes the connection the
  hub logs it and the stack dials again.
- **Failover:** with a primary nothing listens on, `--sc-failover-uri` is dialled.
- **`--sc-accept-hub-without-hello`:** a Connect-Accept without Hello is not
  accepted by default, and is with the option (which logs a warning).
- **Revocation list:** an `issuer-crl.pem` that holds no PEM CRL makes the
  connector refuse every hub (fail closed).
- **Options:** `--sc-failover-uri` alone, a `ws://` or `http://` URI and a
  missing value are refused.

```
python tests/sc/connector_test.py --exe build/BACnetExampleBSCHUB
```

`fake_hub_server.py` can also be run on its own to look at the connector by hand:

```
python tests/sc/fake_hub_server.py --port 47940 --cert-dir certs
# in a separate terminal:
./build/BACnetExampleBSCHUB --sc-hub-uri wss://127.0.0.1:47940/
```

## `hub_cert_test.py` (the hub's own certificate)

Runs the executable itself in a temporary folder, so no hub needs to be
running. It plays the CA with the `cryptography` package.

- **The start-up request:** the first start-up with an empty folder writes
  `key-hub.pem`, `csr-hub.pem` and the `hub/` marker, and no certificate, and
  logs one line naming `hub-cari-request.zip`'s full path. The zip holds the
  CSR (the same one as on disk) and the marker, and no private key. The CSR
  asks for `localhost`, `127.0.0.1` and this computer's IPv4 address in
  subjectAltName and for serverAuth and clientAuth, and its subject is the
  device name. A second start-up logs that the zip already exists and leaves
  it (and the key) untouched; with the zip deleted, a start-up makes it again
  from the same CSR; a key with no CSR is never replaced (no zip, a warning).
- **`--import-cari` refuses**, writing nothing: a response for another key,
  one with no issuer, one whose issuer didn't sign it, an expired
  certificate, a zip with a `../` path, and the request zip itself.
- **`--import-cari` installs** a good response: `opr-hub.pem` is the CA's
  certificate, `iss-1.pem` is the issuer that signed it (even when it is
  listed second in the zip), `iss-2.pem` the other issuer, and the key is
  unchanged. The hub then serves BACnet/SC with the imported certificate.
- **Options this example doesn't have** - `--generate-csr` (the request is made
  at start-up), certificate signing, and the production conveniences of a
  production hub (HTTP, service, config and log files, `--demo-stop-after`, ...)
  - are refused as unknown.

```
python tests/sc/hub_cert_test.py --exe build/BACnetExampleBSCHUB
```

## `file_object_test.py` (the certificate File objects)

A BACnet/SC client (`sc_client.py`); the 4 File objects are read with
ReadProperty/AtomicReadFile through the hub.

```
./build/BACnetExampleBSCHUB --sc-port 4443
# in a separate terminal:
python tests/sc/file_object_test.py --sc-port 4443 --cert-dir certs
```

- `AtomicReadFile(File 1, "Operational Certificate")` returns `opr-hub.pem`
  byte for byte.
- Network Port 2's `Issuer_Certificate_Files` (property 511) has exactly 2
  entries.
- Files 1-4 are all read and compared against the hub's private key; none
  may match.

## `rpm_test.py` (ReadPropertyMultiple, DS-RPM-B)

```
./build/BACnetExampleBSCHUB --sc-port 4443
# in a separate terminal:
python tests/sc/rpm_test.py --sc-port 4443 --cert-dir certs
```

Who-Is through the hub gets an I-Am from 389022. One `ReadPropertyMultiple`
for the Device's `Object_Name` and `Vendor_Identifier` gets one
`ReadPropertyMultipleACK` with both properties correct
(`Object_Name == "Chipkin Example B-SCHUB"`, `Vendor_Identifier == 389`).
`Object_List` has exactly one Network Port, 2 (BACnet/SC), and
`Protocol_Revision` is 30.

## `segmentation_test.py` (segmentation, both directions)

The hub claims `Segmentation_Supported` = `segmented-both`. This checks it:

- `Segmentation_Supported`, `Max_Segments_Accepted` (> 1) and
  `APDU_Segment_Timeout` (> 0) on the Device.
- **Transmit**: the client accepts only 128-octet APDUs, so the hub must
  segment its ReadPropertyMultiple(Device, ALL) answer (2 or more segments).
- **Receive**: a ReadPropertyMultiple request of 1000 property references,
  longer than the hub's 1476-octet max APDU, sent segmented; the hub must
  reassemble it and answer every reference.

```
./build/BACnetExampleBSCHUB --sc-port 4443
# in a separate terminal:
python tests/sc/segmentation_test.py --sc-port 4443 --cert-dir certs
```

## `discovery_test.py` (every listed property reads as a value)

The series' discovery Wire Test (B-SS-CPP `tests/discovery_test.py`), done over
BACnet/SC because the hub has no BACnet/IP port unless started with `--port`: what a client such as
Chipkin BACnet Explorer does when it discovers a device.

- **Who-Is** for 389022 through the hub -> the I-Am.
- **Device `Object_List`** names exactly Device 389022, Analog Input 1, File
  1-4 and Network Port 2. This is the control: a walk over nothing would pass.
- For each object, **`Property_List`** reads, and a ReadProperty of every
  property it lists - plus `Object_Identifier`, `Object_Name`, `Object_Type`
  and `Property_List`, which cl. 12.1.1.4.1 leaves out of the list - returns a
  ReadProperty-ACK. An Error, Reject, Abort or no answer prints an
  `[UNREADABLE]` line and fails the check. The reads are raw ReadProperty
  requests, so a property bacpypes3 has no datatype for is still read and
  checked.

```
./build/BACnetExampleBSCHUB --sc-port 4443
# in a separate terminal:
python tests/sc/discovery_test.py --sc-port 4443 --cert-dir certs
```

## `cert_procedure_test.py` (the clause 19.8.3 certificate procedures)

Drives the hub the way a certificate tool (e.g. the CAS BACnet Explorer's
BACnet/SC certificate page) does, over BACnet/SC (`sc_client.py`). An
acknowledged `ACTIVATE_CHANGES` restarts the hub's listener, which drops this
connection too (after the acknowledgement is sent), so the test reconnects:

- **Add issuer:** File_Size = 0 + AtomicWriteFile a second CA into File 4,
  Changes_Pending, ReinitializeDevice ACTIVATE_CHANGES. Then a device signed
  by the new CA and one signed by the original CA both complete a TLS
  handshake.
- **Removing the only issuer** is refused.
- **Rejected activation:** a combined certificate + key file, or garbage, in
  File 1 -> INVALID_CONFIGURATION_DATA, and the file on disk is unchanged.
- **DISCARD_CHANGES** and **GENERATE_CSR_FILE** through Network Port 2's
  `Command`.
- **Replace operational certificate** (existing CSR, and a new key pair):
  sign the CSR with the second CA, write File 1, activate. The hub then
  presents the new certificate.
- The CSR File (File 2) refuses writes, and ReinitializeDevice COLDSTART is
  refused.

```
python tools/make_test_certs.py --cert-dir hub-certs --devices 1
python tools/make_test_certs.py --cert-dir other-certs --devices 1
./build/BACnetExampleBSCHUB --sc-port 4443 --sc-cert-dir hub-certs
# in a separate terminal:
python tests/sc/cert_procedure_test.py --sc-port 4443 \
    --cert-dir hub-certs --second-issuer-dir other-certs
```

It **rewrites the hub's certificate files** - use a throwaway set, never the
committed `certs/`.

## `cert_files_test.py` (the devices' CARI zips)

Checks what `tools/make_test_certs.py` writes for each device: one file,
`clients/<label>-cari.zip`, and nothing else in `clients/`.

- **The zip:** a valid CARI response with only CARI names.
- **The certificate:** `opr-<label>.pem` is signed by `iss-1.pem` and is for
  `key-<label>.pem` and `csr-<label>.pem`.
- **The readme:** `cert1/response-notes.txt` names each file, says which are
  private, and gives the hub URI.

```
python tools/make_test_certs.py --cert-dir test-certs --devices 1
python tests/sc/cert_files_test.py --cert-dir test-certs
python tests/sc/cert_files_test.py --cert-dir certs        # the committed demo set
```

## CI

`.github/workflows/release.yml` runs every script here on Windows and Linux
for each pull request and tag: `cert_files_test.py` (on a fresh
`tools/make_test_certs.py` set and on the committed demo set),
`hub_cert_test.py`, `connection_limit_test.py`, `run_limit_test.py`,
`startup_test.py`, `ip_port_test.py`, `time_sync_test.py`, `utc_time_sync_test.py`,
`hub_options_test.py`,
`connector_test.py`, `hub_listener_test.py`
(against the demo set, and again with `--sc-accept-device-without-hello`),
`file_object_test.py`, `rpm_test.py`, `segmentation_test.py`,
`discovery_test.py`, and `cert_procedure_test.py` (on throwaway sets).
