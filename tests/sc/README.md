# BACnet/SC transport tests

Verification scripts for `sc_transport/` - see
`../../docs/bacnet-sc-transport-plan.md`'s "Verification" section for what
each one proves.

## `hub_listener_test.py` (V1, V2 - the listener/hub-function half)

```
pip install -r tests/sc/requirements.txt
cmake -P ../scripts/generate-test-certs.cmake   # from the repo root: cmake -P scripts/generate-test-certs.cmake
# in a separate terminal:
./build/BACnetExampleBSCHUB.exe --sc-port 47819 --sc-cert-dir ./certs
# then:
python tests/sc/hub_listener_test.py --port 47819 --cert-dir certs
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
`<label>.crt`/`.key` from `scripts/generate-test-certs.cmake`. The default
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
cmake -P scripts/generate-test-certs.cmake   # once, if certs/ is empty
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
cmake -P scripts/generate-test-certs.cmake   # once, if certs/ is empty
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
