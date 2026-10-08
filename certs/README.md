# DEMO CERTIFICATES - PUBLIC, NOT SECRET

**Every private key here, including the CA's, is published with this example,
so anyone can make a certificate this hub trusts. Use them only for testing on
an isolated network.** For real certificates use a Certificate Authority (the
Chipkin BACnet SC Certificate Authority, BACnet International's BACCARI, or
your own) - see the [README](../README.md#certificates).

This set lets the example run out of the box: `BACnetExampleBSCHUB` reads
`./certs` by default. It was made with
[`tools/make_test_certs.py`](../tools/make_test_certs.py):

```
python tools/make_test_certs.py --cert-dir certs --hub-uri wss://127.0.0.1:4443/ --portable
```

## What is here

The layout is CARI (Certificate Authority Requirements Interchange,
ANSI/ASHRAE 135-2024 Annex AA.2), the format the hub reads.

| File | What it is |
|---|---|
| `cert1/device-389022/port-2/hub/` | Empty: marks Network Port 2 as a hub function. |
| `cert1/device-389022/port-2/opr-hub.pem` | The hub's certificate (File 1, Operational_Certificate_File). Names `localhost` and `127.0.0.1`. |
| `cert1/device-389022/port-2/key-hub.pem` | The hub's private key. **Public in this demo set.** |
| `cert1/device-389022/port-2/csr-hub.pem` | The request the hub's certificate was signed from (File 2). |
| `cert1/issuer/iss-1.pem` | The demo CA's certificate (File 3, Issuer_Certificate_Files) - the hub trusts devices it signed. |
| `ca/ca-cert.pem`, `ca/ca-key.pem` | The demo CA. `tools/make_test_certs.py --add-devices` uses it to sign more devices; the hub never reads it. **Its key is public.** |
| `clients/client-01-cari.zip` ... `client-03-cari.zip` | One CARI response per test device: its certificate, its private key, the issuer and a `cert1/response-notes.txt` explaining each file. |
| `certificates.txt` | Every certificate's serial number, expiry date and SHA-256 fingerprint. |

The hub writes `trusted-issuers.pem` here when it starts (every issuer it
trusts), and `hub-cari-request.zip` (its certificate request, for a CA) if it
isn't here yet; neither is part of the set.

The hub's and devices' certificates expire on 2029-01-10, the CA on
2036-10-05. To make a fresh set, run the command above with `--force`.
