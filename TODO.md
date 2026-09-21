# TODO

Real, verified-absent gaps only - see the series runbook's Definition of Done:
"Every remaining `TODO.md` names a missing customer export verified absent at
the pin, dated, with a stack issue filed [where applicable]." This repository
is canonical for **F-SC**; the gap below is a deliberate spike outcome (see
README.md "BACnet/SC support"), not a stack limitation.

## 1. BACnet/SC File objects (certificate export over BACnet/IP) are not implemented yet (Phase 4, dated 2026-09-20)

**Status update:** the spike roadblock this item used to describe (see
`CHANGELOG.md`) was cleared - `sc_transport/ScTransport` +
`sc_transport/ScTransportRouter` (libwebsockets + OpenSSL, via vcpkg) now
implement BOTH BACnet/SC transport roles for real: mutual TLS 1.3,
subprotocol `hub.bsc.bacnet.org`.

- **Listener** (hub-function accept role, NM-SCH-B): verified end-to-end
  against a hand-built test client (`tests/sc/hub_listener_test.py`) and a
  real peer (`BACnetSCCli.exe`, `Role=node` - Who-Is/I-Am/ReadProperty
  discovery succeeds). See `docs/bacnet-sc-transport-plan.md` Phase 2 and its
  V1-V3.
- **Connector** (hub-connector/initiate role, `ScTransport::Connect()`/
  `Disconnect()`, `--sc-hub-uri`): verified end-to-end against a hand-built
  fake hub (`tests/sc/fake_hub_server.py` - Connect-Request/Connect-Accept
  exchange, `Connected`/`Disconnected` status, and confirmation that the
  STACK - not `ScTransport` - re-dials after a lost connection) and a real
  hub (`BACnetSCCli.exe`, `Role=hub` - the example's own hub-connector state
  reaches `ConnectedPrimary`). See `docs/bacnet-sc-transport-plan.md` Phase 3
  and its V4-V5.

**What's still missing:** the four read-only File objects serving
`hub.crt`/`hub.csr`/`ca.crt` over BACnet/IP (`BACnetStack_AddFileObject` +
`SetBACnetSCCertificateFileObjects`) and the two dead certificate callbacks
(`RegisterCallbackValidateBACnetSCOperationalCertificate`,
`RegisterCallbackGenerateBACnetSCCertificateSigningRequest`, which have zero
call sites in the stack - see the plan's fact 10). It is Phase 4 of
`docs/bacnet-sc-transport-plan.md` ("File objects").

**Not filed as a stack issue** - this remaining gap is this example's own
scope (Phase 4 of the plan), not a stack limitation.
