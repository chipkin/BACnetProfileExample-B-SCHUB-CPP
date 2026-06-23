# Plan (STUB): B-SCHUB (BACnet/SC Hub) — C++ example

> **STATUS: STUB.** Seed facts below. Expand from
> [`bacnet-profile-plan-template.md`](../../bacnet-profile-plan-template.md) after the
> sample plans ([B-LD](../../BACnetProfileExample-B-LD-CPP/docs/plan.md),
> [B-BC](../../BACnetProfileExample-B-BC-CPP/docs/plan.md)) are reviewed.

**Profile:** B-SCHUB · **Family:** Annex L.7 (Miscellaneous) · **Role:** B ·
**Archetype:** Infrastructure · **Difficulty:** 5/5 (**highest uncertainty**) ·
**Phase:** B (deferred — infrastructure) — **SPIKE BEFORE PLANNING**

**Thesis:** a **BACnet Secure Connect (SC) hub** — accepts SC node connections over
**TLS/WebSocket** and relays their traffic. Fundamentally different transport from
the BACnet/IP UDP socket every other example uses.

## Required BIBBs (profiles.md L.7)
`DS-RP-B; DM-DDB-B, DM-DOB-B, DM-DCC-B, NM-SCH-B`.

## Services to enable
- ReadProperty (1), DCC (17), baseline discovery, + the SC hub function (NM-SCH-B).

## Objects (baseline + )
- An **SC Network Port** (`BACnet/SC` datalink) instead of / alongside BACnet/IP.

## Shared features
- **DEFINE:** F-SC (BACnet/SC transport + NM-SCH-B hub).
- **REUSE:** F-DCC (B-ASC).

## Known stack gaps — **the load-bearing risk (master plan §7 risk 4)**
- The `common/` helper is **BACnet/IP UDP only**. SC needs TLS + WebSocket + certs
  — a whole new datalink. profiles.md: ✅ S73 (NM-SCH-B; 376 `*SC*:*HubFunction*`
  gtests), so the **stack** supports SC, but wiring it into this example series is
  the open problem.

## Notes / open questions — **resolve via a spike first**
1. Does the standard DLL expose an SC datalink API the example can drive, or is SC
   configured externally? Confirm before committing to a code plan.
2. Does this example need a **second transport helper** (`common/` is IP-only), or a
   documented "SC endpoint configured outside the example" boundary?
3. Certificate/TLS setup is required to run SC — how does a tutorial keep that
   minimal and copy-pasteable?
4. **Recommendation:** schedule a dedicated spike; do not estimate the full example
   until the transport question is answered. This is the riskiest item in the plan.
