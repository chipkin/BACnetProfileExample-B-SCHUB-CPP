# TODO

Real, verified-absent gaps only - see the series runbook's Definition of Done:
"Every remaining `TODO.md` names a missing customer export verified absent at
the pin, dated, with a stack issue filed [where applicable]." This repository
is canonical for **F-SC**; the gap below is a deliberate spike outcome (see
README.md "BACnet/SC support"), not a stack limitation.

## 1. BACnet/SC hub-connector (initiate) transport is not implemented yet (Phase 3, dated 2026-09-20)

**Status update:** the spike roadblock this item used to describe (see
`CHANGELOG.md`) was cleared - `sc_transport/ScTransport` +
`sc_transport/ScTransportRouter` (libwebsockets + OpenSSL, via vcpkg) now
implement the **listener** (hub-function accept role, NM-SCH-B) for real:
mutual TLS 1.3, subprotocol `hub.bsc.bacnet.org`, and verified end-to-end
against both a hand-built test client (`tests/sc/hub_listener_test.py`) and a
real peer (`BACnetSCCli.exe`, `Role=node` - Who-Is/I-Am/ReadProperty discovery
succeeds). See `docs/bacnet-sc-transport-plan.md` Phase 2 and its V1-V3.

**What's still missing:** `ScTransport::Connect()`/`Disconnect()` (the hub
**connector**/initiate role - `CallbackInitiateWebsocket`/
`CallbackDisconnectWebsocket` in `main.cpp`) are still honest stubs: they log
what the stack asked for and return `false`/no-op rather than claiming an
outbound connection this example does not make. This hub-only example does
not need a connector to answer a node's own requests (the hub function
delivers locally - see the plan's open risk #8, proven by V3 above), so this
gap does not block NM-SCH-B. It is Phase 3 of
`docs/bacnet-sc-transport-plan.md` ("Connector").

Also still missing (Phase 4 of the same plan): the four read-only File
objects serving `hub.crt`/`hub.csr`/`ca.crt` over BACnet/IP
(`BACnetStack_AddFileObject` + `SetBACnetSCCertificateFileObjects`) and the
two dead certificate callbacks
(`RegisterCallbackValidateBACnetSCOperationalCertificate`,
`RegisterCallbackGenerateBACnetSCCertificateSigningRequest`, which have zero
call sites in the stack - see the plan's fact 10).

**Not filed as a stack issue** - both remaining gaps are this example's own
scope (Phase 3/4 of the plan), not a stack limitation.
