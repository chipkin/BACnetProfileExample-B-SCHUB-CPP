# BACnet/SC Hub (B-SCHUB) - Fact Sheet

**Chipkin Automation Systems** · Version 1.4.0 ·
<https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP>

A **BACnet Secure Connect hub** built on the
[CAS BACnet Stack](https://store.chipkin.com/services/stacks/bacnet-stack).
BACnet/SC devices connect to it over TLS 1.3 WebSockets and it relays their
BACnet traffic between them. A BACnet/IP port keeps it visible to existing
BACnet/IP tools, or can be turned off for a BACnet/SC-only site.

**Intended use:** evaluation, interoperability testing and development of
BACnet/SC devices and networks. This edition accepts **up to 4 BACnet/SC
connections**. For a production hub with more connections, or to build your
own product on the CAS BACnet Stack, contact **support@chipkin.com**.

## At a glance

| Item | Details |
|---|---|
| **BACnet device profile** | B-SCHUB - BACnet/SC Hub (ANSI/ASHRAE 135 Annex L) |
| **BIBBs** | NM-SCH-B, DS-RP-B, DS-RPM-B, DM-DDB-B, DM-DOB-B, DM-DCC-B |
| **BACnet Protocol_Revision** | 30 |
| **Data links** | BACnet/SC (Annex AB) hub function, plus optional hub connector with failover; BACnet/IP (Annex J), optional |
| **Services executed** | ReadProperty, ReadPropertyMultiple, Who-Is/I-Am, Who-Has/I-Have, DeviceCommunicationControl, AtomicReadFile, AtomicWriteFile and WriteProperty (certificate files), ReinitializeDevice (ACTIVATE_CHANGES, WARMSTART) |
| **Objects** | Device, Analog Input, Network Port (BACnet/IP and BACnet/SC), File (4 certificate files) |
| **BACnet/SC connections** | Up to 4 at a time (this edition) |
| **Platforms** | Windows 10/11 and Server 2016+ (x64); Linux x64 (current distributions; source build for others) |
| **Packaging** | Windows installer with a Windows service; Debian/Ubuntu `.deb` and Linux archive with a systemd service; signed downloads and checksums |

## Security

- **TLS 1.3 only**, with **mutual certificate authentication** for every
  BACnet/SC connection; WebSocket subprotocol `hub.bsc.bacnet.org`.
- **Certificate management over BACnet** (ANSI/ASHRAE 135 clause 19.8.3):
  replace the hub's certificate and add a second trusted CA remotely; new
  certificates are validated before they are used, so a mistake can't lock
  the hub out.
- **Certificate revocation** with CRLs, fail-closed.
- **Connection rate limiting** per source address and in total, before the
  TLS handshake; per-connection transmit limits.
- **Audit trail** naming each device by address, certificate, VMAC and
  device UUID.
- **BACnet/SC-only mode** for sites that allow no unencrypted BACnet traffic.
- Lab certificate generator for testing; guide for production PKI.

## Operations

- Status page, `/health` (for monitors and load balancers) and `/metrics`
  over HTTP or HTTPS.
- Rotating log files; configuration file; per-site device name and network
  numbers.
- Software bill of materials (CycloneDX) with every release.

## Documents

- **User manual** - `manual.pdf`
- **PICS** (Protocol Implementation Conformance Statement) - `PICS.pdf`
- **Releases** - <https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/releases>
- **CAS BACnet Stack** - <https://store.chipkin.com/services/stacks/bacnet-stack>

**Contact:** Chipkin Automation Systems · support@chipkin.com ·
<https://store.chipkin.com/contact-us>
