# BACnet/SC tests

Verification scripts for the B-SCHUB example: the BACnet/SC transport
(`sc_transport/`), the hub's certificates, the certificate File objects and
procedures, and the connection limit. CI runs all of them on Windows and Linux
(see [CI](#ci) below).

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
  BACnet/SC devices and names sales@chipkin.com, before the `ready` line;
- four devices are accepted; a fifth gets a BVLC-Result NAK, and the hub logs
  the connection-limit warning (naming sales@chipkin.com) once;
- the limit is fixed: `--sc-max-hub-connections 5` is refused as an unknown
  option.

```
python tests/sc/connection_limit_test.py --exe build/BACnetExampleBSCHUB
```

## `hub_cert_test.py` (the hub's own certificate)

Runs the executable itself in a temporary folder, so no hub needs to be
running. It plays the CA with the `cryptography` package.

- **`--generate-csr`** writes `key-hub.pem`, `csr-hub.pem` and the `hub/`
  marker, and no certificate. `hub-cari-request.zip` holds the CSR (the same
  one as on disk) and the marker, and no private key. The CSR asks for
  `localhost`, `127.0.0.1` and this computer's IPv4 address in subjectAltName
  and for serverAuth and clientAuth, and its subject is the device name.
  Running it again keeps the key.
- **`--import-cari` refuses**, writing nothing: a response for another key,
  one with no issuer, one whose issuer didn't sign it, an expired
  certificate, a zip with a `../` path, and the request zip itself.
- **`--import-cari` installs** a good response: `opr-hub.pem` is the CA's
  certificate, `iss-1.pem` is the issuer that signed it (even when it is
  listed second in the zip), `iss-2.pem` the other issuer, and the key is
  unchanged. The hub then serves BACnet/SC with the imported certificate.
- **Options this example doesn't have** - certificate signing, and the
  production conveniences of a production hub (HTTP, service, config
  and log files, the hub connector, more connections, ...) - are refused as
  unknown.

```
python tests/sc/hub_cert_test.py --exe build/BACnetExampleBSCHUB
```

## `file_object_test.py` (the certificate File objects)

A BACnet/IP client (`bacpypes3`); the 4 File objects are read with
ReadProperty/AtomicReadFile on Network Port 1.

```
./build/BACnetExampleBSCHUB
# in a separate terminal:
python tests/sc/file_object_test.py --target 127.0.0.1 --target-port 47808 --cert-dir certs
```

- `AtomicReadFile(File 1, "Operational Certificate")` returns `opr-hub.pem`
  byte for byte.
- Network Port 2's `Issuer_Certificate_Files` (property 511) has exactly 2
  entries.
- Files 1-4 are all read and compared against the hub's private key; none
  may match.

## `rpm_test.py` (ReadPropertyMultiple, DS-RPM-B)

```
./build/BACnetExampleBSCHUB --port 47870
# in a separate terminal:
python tests/sc/rpm_test.py --target 127.0.0.1 --target-port 47870
```

One `ReadPropertyMultiple` for the Device's `Object_Name` and
`Vendor_Identifier` gets one `ReadPropertyMultipleACK` with both properties
correct (`Object_Name == "Chipkin Example B-SCHUB"`, `Vendor_Identifier == 389`).

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
./build/BACnetExampleBSCHUB --port 47870
# in a separate terminal:
python tests/sc/segmentation_test.py --target 127.0.0.1 --target-port 47870
```

## `cert_procedure_test.py` (the clause 19.8.3 certificate procedures)

Drives the hub the way a certificate tool (e.g. the CAS BACnet Explorer's
BACnet/SC certificate page) does, over BACnet/IP:

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
./build/BACnetExampleBSCHUB --port 47870 --sc-port 4443 --sc-cert-dir hub-certs
# in a separate terminal:
python tests/sc/cert_procedure_test.py --target-port 47870 --sc-port 4443 \
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
`hub_cert_test.py`, `connection_limit_test.py`, `hub_listener_test.py`
(against the demo set, and again with `--sc-accept-device-without-hello`),
`file_object_test.py`, `rpm_test.py`, `segmentation_test.py`, and
`cert_procedure_test.py` (on throwaway sets).
