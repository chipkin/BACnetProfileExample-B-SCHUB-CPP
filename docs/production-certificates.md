# Production certificates

`BACnetExampleBSCHUB --generate-certs` makes a throwaway lab CA so you can try
the hub in minutes. A site that deploys the hub should use its own
certificate authority instead. This guide covers:

- [How BACnet/SC trust works on this hub](#how-trust-works)
- [Using a site or enterprise CA](#using-a-site-or-enterprise-ca)
- [Getting the hub's certificate signed](#getting-the-hubs-certificate-signed)
- [Installing it (over BACnet or on disk)](#installing-the-certificate)
- [Rotating certificates before they expire](#rotating-certificates)
- [Changing the CA](#changing-the-ca)
- [Revoking a device](#revoking-a-device)
- [What the certificates should contain](#what-the-certificates-should-contain)
- [Protecting private keys](#protecting-private-keys)

The file names below are the defaults in `--sc-cert-dir` (`./certs`).

## How trust works

BACnet/SC runs over TLS 1.3 with mutual authentication. The hub accepts a
device when the device's certificate chains to one of the hub's **issuer
certificates**, and a device accepts the hub when the hub's certificate chains
to one of *its* issuer certificates. Nothing else is checked by default: not
the host name, not the subject.

The hub keeps its certificates in four BACnet File objects, which Network
Port 2 ("BACnet SC") points at:

| File object | File on disk | Holds |
|---|---|---|
| File 1 | `operational-certificate.pem` | The hub's own certificate (plus any intermediate CA certificates, see below). |
| File 2 | `certificate-signing-request.pem` | A certificate signing request (CSR) for the hub's private key. Read-only. |
| File 3 | `issuer-certificate.pem` | Issuer certificate slot 1. |
| File 4 | `issuer-certificate-2.pem` | Issuer certificate slot 2. Serves slot 1's certificate until something is written to it. |

The private key, `private-key.pem`, has no File object and is never served
over BACnet. TLS trusts every certificate in both issuer slots; the hub
writes them together into `trusted-issuers.pem`.

## Using a site or enterprise CA

Use a CA dedicated to BACnet/SC, or at least a dedicated issuing CA under
your organization's root. **Do not use a public web CA** that browsers trust:
the hub would then accept any certificate that CA has ever issued, for any
website.

Two common layouts:

**One issuing CA (simplest).** The CA that signs the device certificates goes
in slot 1 (File 3). Slot 2 stays free for a future CA change.

**Root plus intermediate.** Your root CA signs an intermediate, and the
intermediate signs the hub and device certificates. Either:

- put the **root in slot 1** and the **intermediate in slot 2**. Devices only
  need to present their own certificate. This uses both slots, so a CA change
  later means replacing one of them (see [Changing the CA](#changing-the-ca)).
- or put only the **root in slot 1**, and have the hub and every device send
  the intermediate with their own certificate (their certificate file holds
  the device certificate followed by the intermediate). Slot 2 stays free.
  The hub sends whatever is in `operational-certificate.pem`, so append the
  intermediate there.

Every device needs the same issuer certificate(s) as trust anchors for the
hub's certificate.

## Getting the hub's certificate signed

The hub can't generate a new key pair on request (the Network Port
`GENERATE_CSR_FILE` command isn't available yet, see
[#10](https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP/issues/10)).
So the key pair and CSR are made once, on the hub's own machine, and the key
never leaves it:

```bash
cd certs
# A new ECDSA P-256 key for the hub. Never copy this file off the machine.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private-key.pem
chmod 600 private-key.pem            # Windows: see "Protecting private keys"
# The CSR the CA will sign. The subject is up to your site's naming policy.
openssl req -new -key private-key.pem -subj "/O=Example Site/CN=BACnet SC Hub 1" \
    -out certificate-signing-request.pem
```

Send `certificate-signing-request.pem` to your CA. The CSR is public; it can
also be read over BACnet from File 2 (AtomicReadFile) by a certificate tool.

If you run the CA with OpenSSL, sign it with the extensions a BACnet/SC hub
certificate needs (it acts as a TLS server to devices and as a TLS client when
it connects out to another hub):

```bash
cat > hub-ext.cnf <<'EOF'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:bacnet-hub.example.site, IP:10.0.0.20
EOF
openssl x509 -req -in certificate-signing-request.pem -CA issuer-ca.pem -CAkey issuer-ca-key.pem \
    -CAcreateserial -days 730 -sha256 -extfile hub-ext.cnf -out operational-certificate.pem
```

Check the result before installing it:

```bash
openssl verify -CAfile issuer-ca.pem operational-certificate.pem
# the two lines must match: the certificate belongs to the hub's key
openssl x509 -in operational-certificate.pem -noout -pubkey | openssl sha256
openssl pkey -in private-key.pem -pubout | openssl sha256
```

## Installing the certificate

**Over BACnet** (no restart, validated before use). With a BACnet/SC
certificate tool such as the
[CAS BACnet Explorer](https://store.chipkin.com/products/tools/cas-bacnet-explorer), or any client that can do
WriteProperty, AtomicWriteFile and ReinitializeDevice:

1. Write the CA certificate to File 3 (and File 4 if you use two issuers).
2. Write the hub certificate to File 1.
3. Send ReinitializeDevice `ACTIVATE_CHANGES` (with the `dcc-password`, if one
   is set).

The hub checks the new set first: every file must be a PEM certificate, at
least one issuer must remain, and the hub certificate must match its private
key and chain to an issuer. If any check fails the hub answers
`INVALID_CONFIGURATION_DATA` and keeps its current certificates, so a mistake
can't lock it out. See the manual's
[Managing certificates over BACnet](manual.md#7-managing-certificates-over-bacnet).

**On disk.** Stop the hub, put `operational-certificate.pem`,
`private-key.pem` and `issuer-certificate.pem` (and optionally
`issuer-certificate-2.pem`) in `--sc-cert-dir`, and start it. The start-up log
shows each certificate's subject, days until expiry, and whether the private
key matches.

Remove the lab files (`issuer-private-key.pem`, `clients/`) from a production
hub's certificate folder.

## Rotating certificates

The hub logs a warning at start-up when a certificate expires in less than
30 days, but it doesn't renew anything itself. Put the expiry dates in your
site's calendar or monitoring (`openssl x509 -enddate -noout -in
operational-certificate.pem`).

**Renewing the hub's certificate** (same key, same CA): have the CA sign the
existing CSR again, then install the new certificate over BACnet (write File 1,
`ACTIVATE_CHANGES`). Devices reconnect within seconds; nothing changes on
their side because the CA is the same.

**Renewing with a new key**: make a new key and CSR on the hub machine (above),
have it signed, then stop the hub, replace `private-key.pem` and
`operational-certificate.pem` together, and start it. (A new key can't be
installed over BACnet: the hub only accepts a certificate for the key it
already has.)

**Device certificates** are renewed on each device the same way; the hub
needs no change as long as the issuing CA stays the same.

## Changing the CA

Moving the whole site to a new CA without an outage uses both issuer slots:

1. **Trust both.** Write the new CA to the hub's free issuer slot (File 4, or
   whichever slot doesn't hold the CA in use) and activate. Add the new CA
   to every device's trusted issuers the same way. Devices signed by either
   CA are accepted.
2. **Reissue.** Sign new device certificates with the new CA and install them,
   device by device. Then sign the hub's CSR with the new CA and install it on
   the hub (File 1).
3. **Retire the old CA.** Once no device uses a certificate from the old CA,
   overwrite its slot with the new CA (both slots may hold the same CA) and
   activate. Remove the old CA from the devices.

A device whose certificate is from a CA the hub no longer trusts can't
connect, and the hub logs `SC TLS handshake REJECTED` with the reason.

## Revoking a device

Put your CA's certificate revocation list in `issuer-crl.pem` in the hub's
certificate folder. The hub refuses any device whose certificate is on it, and
picks up a new or changed file within 5 seconds (BACnet/SC restarts, devices
reconnect, revoked ones are refused). With OpenSSL as the CA:

```bash
openssl ca -config ca.cnf -revoke device-07.pem     # mark it revoked in the CA database
openssl ca -config ca.cnf -gencrl -crldays 30 -out issuer-crl.pem
```

With two issuers, put a CRL from each in the file, one after the other.
Revocation checking fails closed: while `issuer-crl.pem` exists, a device
whose issuer has no CRL in it, or whose CRL is past its next-update date, is
refused. Publish a fresh CRL before the old one expires (`-crldays`). Without
the file, revocation isn't checked, and the only way to cut off one device is
to move the rest of the site to a new CA.

## What the certificates should contain

BACnet/SC identifies devices by their certificate chain, not by host name.
The hub doesn't check the host name when it connects out to another hub, and
it doesn't match a device's certificate to its BACnet/SC UUID. So the subject
and subjectAltName are mostly for people:

- **Subject Common Name**: something an operator recognises in a log, such as
  the site and device name (`O=Example Site, CN=AHU-3 controller`). The hub
  logs the device's certificate subject when it connects, so a meaningful name
  makes the audit trail useful.
- **subjectAltName on the hub**: the DNS names and IP addresses devices use to
  reach it. The hub doesn't need it, but some BACnet/SC devices do check the
  host name, and they will refuse a hub certificate without a matching entry.
- **Key usage**: `digitalSignature`.
  **Extended key usage**: `serverAuth, clientAuth` for the hub; `clientAuth`
  for devices (add `serverAuth` if the device also accepts direct
  connections).
- **Algorithm**: ECDSA P-256 with SHA-256 (what `--generate-certs` uses) or
  RSA 2048 or larger. Every device must support the algorithm your CA uses.
- **Validity**: 1-2 years for hub and device certificates is common. Longer
  validity means fewer renewals but a longer window if a key leaks.

## Protecting private keys

- **The hub's key** (`private-key.pem`) must be readable only by the account
  that runs the hub:
  - Linux: `chown bacnethub: private-key.pem && chmod 600 private-key.pem`
  - Windows: `icacls private-key.pem /inheritance:r /grant:r "%USERNAME%:F"`
    (or the service account's name when the hub runs as a service).
- **Keep the CA's key off the hub.** `issuer-private-key.pem` is only created
  by `--generate-certs` for lab use. A production CA key belongs on the CA,
  ideally offline or in an HSM.
- **Back up** the hub's key and certificate somewhere as protected as the
  hub itself, or plan to reissue from a new CSR if the machine is lost.
- **HSM or TPM.** This example loads its key from a PEM file through OpenSSL.
  Keeping the key in a TPM or HSM needs an OpenSSL provider (for example the
  `tpm2` or `pkcs11` provider) and a small change in
  `sc_transport/ScTransport.cpp` to load the key through it instead of from a
  file. It isn't built in.
