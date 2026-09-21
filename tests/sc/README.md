# BACnet/SC transport tests

Verification scripts for `sc_transport/` - see
`../../docs/bacnet-sc-transport-plan.md`'s "Verification" section for what
each one proves.

## `hub_listener_test.py` (V1, V2 - Phase 2, the listener/hub-function half)

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

## `fake_hub_server.py` (V4 - Phase 3, the connector half)

Not created yet - the connector half of `ScTransport` (`Connect()`) is still a
stub (see `sc_transport/ScTransport.h`'s class-header comment). This script
lands with Phase 3.

## V3 (a real peer - `BACnetSCCli.exe`)

Manual, against `C:\dev\chipkin\BACnetSCCli\app\build\Release\BACnetSCCli.exe`
in `Role=node` mode - see the plan's V3 for the exact config. Not run by any
script here.
