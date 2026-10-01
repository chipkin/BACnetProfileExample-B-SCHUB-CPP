# BACnet/SC transport tests

Verification scripts for `sc_transport/` - see
`../../docs/bacnet-sc-transport-plan.md`'s "Verification" section for what
each one proves.

## `hub_listener_test.py` (V1, V2 - the listener/hub-function half)

```
pip install -r tests/sc/requirements.txt
./build/BACnetExampleBSCHUB --generate-certs   # from the repo root
# in a separate terminal:
./build/BACnetExampleBSCHUB.exe --sc-port 4443 --sc-cert-dir ./certs
# then:
python tests/sc/hub_listener_test.py --port 4443 --cert-dir certs
```

Checks:

- **V1** - TLS 1.3 negotiates, the server echoes the `hub.bsc.bacnet.org`
  subprotocol; negative cases (no client cert, TLS 1.2, wrong subprotocol, a
  text frame) are all refused/rejected/closed(1003).
- **V2** - a hand-built BVLC-SC Connect-Request (function 0x06) gets a
  Connect-Accept (0x07) back; the test then closes the socket abruptly. Watch
  the example's own console for the peer-eviction log line
  (`BACnet/SC: peer "..." disconnected (status=3 ...)`) - the script does not
  have a handle on a separately-started example process's stdout, so that half
  of V2 is a manual check, not an assertion in the script.

Exit code 0 = every automated check passed.

`--client-cert <label>` picks which client certificate to connect with:
`clients/<label>/` from `BACnetExampleBSCHUB --generate-certs`, or
`<label>.crt`/`.key` from an older certificate folder. The default
is `node` if `node.crt` exists, otherwise `client-01`. For example, after
`BACnetExampleBSCHUB --add-client-certs 1 --cert-label late` while the hub is
running, `--client-cert late-01` confirms the hub trusts the new certificate
without a restart. All the scripts here find the hub's and issuer's files
under either naming through `cert_paths.py`.

## V3 (a real peer - `BACnetSCCli.exe`)

Manual, against `C:\dev\chipkin\BACnetSCCli\app\build\Release\BACnetSCCli.exe`
in `Role=node` mode - see the plan's V3 for the exact config. Not run by any
script here.

## `fake_hub_server.py` (V4 - the connector half)

A mutual-TLS `websockets` server offering the `hub.bsc.bacnet.org`
subprotocol, standing in as a fake hub so the CONNECTOR half
(`ScTransport::Connect()`) can be tested without a second real hub.

```
pip install -r tests/sc/requirements.txt
./build/BACnetExampleBSCHUB --generate-certs   # once, if certs/ is empty
python tests/sc/fake_hub_server.py --port 47820 --cert-dir certs
# in a separate terminal:
./build/BACnetExampleBSCHUB.exe --sc-hub-uri wss://127.0.0.1:47820/ --sc-cert-dir ./certs
```

Watch `fake_hub_server.py`'s own stdout for `Connect-Request received` /
`Connect-Accept sent` (it echoes the Connect-Request's own `messageId` back -
see the script's own docstring for why that specific detail is load-bearing,
not just "any well-formed Connect-Accept"), and the EXAMPLE's stdout for
`BACnet/SC: connected to hub` and a `CallbackBACnetSCStateChange` line
showing a connected state. Stop `fake_hub_server.py` (Ctrl+C, or run it with
`--once`) and confirm the example logs `BACnet/SC: hub connection "..." closed
(closeCode=...)` / a Disconnected state, and that the STACK - not
`ScTransport` - is what re-dials afterwards (`ScTransport::Connect()` never
calls itself; see `ScTransport.h`'s "NO AUTO-RECONNECT" note).

## V5 (connector vs. a real hub)

Manual, against `BACnetSCCli.exe` in `Role=hub` mode (or a second local
instance of this same example) - see the plan's V5. Not run by any script
here.

## `file_object_test.py` (V6 - the certificate/CSR File objects)

A real BACnet/IP client (`bacpypes3`) - no BACnet/SC connection needed, since
these 4 File objects are read over plain ReadProperty/AtomicReadFile on
Network Port 1.

```
pip install -r tests/sc/requirements.txt
./build/BACnetExampleBSCHUB --generate-certs   # once, if certs/ is empty
./build/BACnetExampleBSCHUB.exe --sc-cert-dir ./certs
# in a separate terminal:
python tests/sc/file_object_test.py --target 127.0.0.1 --target-port 47808 --cert-dir certs
```

Checks:

- `AtomicReadFile(File 1, "Operational Certificate")` returns the bytes of `certs/hub.crt`
  byte-for-byte.
- Network Port 2's `Issuer_Certificate_Files` (property 511) has exactly 2
  entries.
- Negative test: File objects 1-4 are all read via AtomicReadFile and compared
  against `certs/hub.key` - none may match (the private key has no File
  object at all, so this proves the negative rather than assuming it).

Exit code 0 = every check passed.

## `rpm_test.py` (V7 - ReadPropertyMultiple, DS-RPM-B)

A real BACnet/IP client (`bacpypes3`) - confirms `SERVICE_READ_PROPERTY_MULTIPLE`
answers a real multi-property request rather than erroring/aborting.

```
pip install -r tests/sc/requirements.txt
./build/BACnetExampleBSCHUB.exe --port 47870
# in a separate terminal:
python tests/sc/rpm_test.py --target 127.0.0.1 --target-port 47870
```

Checks: a single `ReadPropertyMultiple` request for the Device object's
`Object_Name` + `Vendor_Identifier` gets back one `ReadPropertyMultipleACK`
(not an Error/Reject/Abort) with both properties decoded and correct
(`Object_Name == "Chipkin Example B-SCHUB"`, `Vendor_Identifier == 389`).

Exit code 0 = every check passed.

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
./build/BACnetExampleBSCHUB.exe --port 47870
# in a separate terminal:
python tests/sc/segmentation_test.py --target 127.0.0.1 --target-port 47870
```

Exit code 0 = every check passed.

## `cert_procedure_test.py` (the clause 19.8.3 certificate procedures)

Drives the hub the way a certificate tool (e.g. the CAS BACnet Explorer's
BACnet/SC certificate page) does, over plain BACnet/IP:

- **Add issuer:** File_Size = 0 + AtomicWriteFile a second CA into File 4,
  Changes_Pending, ReinitializeDevice ACTIVATE_CHANGES. Then a client signed
  by the new CA and one signed by the original CA both complete a TLS
  handshake.
- **Rejected activation:** garbage in File 1 -> INVALID_CONFIGURATION_DATA,
  and the file on disk is unchanged.
- **Replace operational certificate (existing CSR):** read File 2, sign it
  with the second CA, write File 1, activate. The hub then presents the new
  certificate.
- The CSR File (File 2) refuses writes, and ReinitializeDevice COLDSTART is
  refused.

```
BACnetExampleBSCHUB --sc-cert-dir hub-certs --generate-certs 1
BACnetExampleBSCHUB --sc-cert-dir other-certs --generate-certs 1
BACnetExampleBSCHUB --port 47870 --sc-port 4443 --sc-cert-dir hub-certs
# in a separate terminal:
python tests/sc/cert_procedure_test.py --target-port 47870 --sc-port 4443 \
    --cert-dir hub-certs --second-issuer-dir other-certs
```

It **rewrites the hub's certificate files** - use a throwaway set.

## `http_test.py` (the HTTP endpoints)

The status page, `/health`, `/metrics`, and `POST /certs/<slot>`: missing and
wrong tokens (401), a malformed certificate (400, file unchanged), a valid
upload (200), a CSR-slot upload that isn't a request (400) and the per-client
rate limit (429, run last).

```
BACnetExampleBSCHUB --generate-certs 1
printf 'http-upload-token = test-token-123
' > http-test.conf
BACnetExampleBSCHUB --config http-test.conf --http-port 18080
# in a separate terminal:
python tests/sc/http_test.py --http-port 18080 --token test-token-123 --cert-dir certs
```

Without `--token` it only checks that the upload endpoint is disabled (503).
Exit code 0 = every check passed.

## `cert_files_test.py` (client files for Windows tools)

Checks each `clients/<label>/` folder from `--generate-certs`: `<label>.pfx`
loads with an empty password and holds the folder's certificate, matching key
and issuer; `issuer-certificate.cer` is the issuer in DER; and
`yabe-bacnetsc.config` names the hub URI and both files by absolute path.

```
BACnetExampleBSCHUB --sc-cert-dir certs --generate-certs 1
python tests/sc/cert_files_test.py --cert-dir certs
```

## `csr_test.py` (`--generate-csr` and `--sign-csr`)

Runs the executable in a temporary certificate folder, so no hub needs to be
running. `--generate-csr` should write a P-256 key and a valid CSR. `--sign-csr`
should sign that CSR back into its own folder (with the `.pfx`/YABE files), and
also sign a CSR made elsewhere, PEM or DER. That certificate keeps the CSR's
subject and key, gets EKU clientAuth only, and the folder holds no private
key. The test also checks refusals: a broken signature, RSA 1024, a file that
isn't a CSR, a folder that already has a certificate, and a folder whose key
isn't the CSR's.

```
python tests/sc/csr_test.py --exe build/Release/BACnetExampleBSCHUB.exe
```

To check that the hub accepts such a certificate over TLS, sign a
`--generate-csr` request and connect with it:
`hub_listener_test.py --client-cert <label>`.

## `keylog_test.py` (`--sc-keylog-file`, issue #68)

Starts the executable on free ports in a temporary folder. For each BACnet/SC
role, Python's `ssl` module is the other end, with its own `keylog_filename`,
and the hub's key log must hold the same five TLS 1.3 secrets for the same
client random. The roles are the hub function (a device connecting in) and
the hub connector (`--sc-hub-uri` to a TLS server the test runs). The test
also checks that HTTPS status-page sessions are *not* logged, `/health`'s
`tls_keylog`, the start-up warning, and that start-up fails for a key log
file that can't be opened.

```
python tests/sc/keylog_test.py --exe build/Release/BACnetExampleBSCHUB.exe
```

## CI

`.github/workflows/release.yml` runs every script here on Windows and Linux
for each pull request: `hub_listener_test.py` (normally and with
`--bacnet-ip off`), `file_object_test.py`, `rpm_test.py`, `http_test.py`
(upload disabled, then enabled with a token, device name, network numbers and
a log file), `fake_hub_server.py` against the connector, and
`cert_procedure_test.py`, `cert_files_test.py`, `csr_test.py` and `keylog_test.py`, plus the
connection-limit refusal.
