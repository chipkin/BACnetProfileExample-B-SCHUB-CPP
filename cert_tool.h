// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_CERT_TOOL_H
#define BSCHUB_EXAMPLE_CERT_TOOL_H

// cert_tool.h
// =============================================================================
// Lab certificate generation for this example's BACnet/SC hub, built into the
// executable itself (OpenSSL is already linked for the SC transport), so a
// user needs no separate `openssl` binary:
//
//   --generate-certs [n]      A fresh set in --sc-cert-dir: a lab CA
//                             (ca.crt/ca.key), this hub's own operational
//                             certificate (hub.crt/hub.key, plus hub.csr for
//                             Network Port 2's CSR File object) and n labeled
//                             client certificates (default 3) for the peers
//                             that connect to the hub.
//   --add-client-certs [n]    n MORE client certificates (default 1), signed
//                             by the ca.crt/ca.key ALREADY in --sc-cert-dir, so
//                             every existing peer and the running hub keep
//                             trusting them. Numbering continues after the
//                             highest existing label.
//   --cert-label <prefix>     Label prefix for client certificates. Default
//                             "client", giving client-01, client-02, ...
//
// Every certificate is LABELED twice: in its file names (client-01.crt /
// client-01.key) and in its subject Common Name
// ("Chipkin Example B-SCHUB client-01"), so a peer's certificate can be traced
// back to its files from the hub's logs or a TLS capture. Every run also
// appends to certificates.txt in the same directory: one line per certificate
// with its label, files, serial number, expiry and SHA-256 fingerprint.
//
// Same key and certificate profile as scripts/generate-test-certs.cmake:
// ECDSA P-256, SHA-256, CA valid 10 years, leaves 825 days; the hub gets EKU
// serverAuth+clientAuth with SAN localhost/127.0.0.1/<hostname>, clients get
// EKU clientAuth.
//
// LAB TESTING ONLY. A real deployment uses its own PKI - see README.md
// "BACnet/SC support".
// =============================================================================

#include <string>

namespace CertTool {

static const unsigned DEFAULT_GENERATE_CLIENT_COUNT = 3;
static const unsigned DEFAULT_ADD_CLIENT_COUNT = 1;
static const char* const DEFAULT_CLIENT_LABEL = "client";

// Creates ca.*, hub.* and `clientCount` labeled client certificates in
// certDir (created if missing). Refuses to touch an existing ca.crt, ca.key,
// hub.crt or hub.key unless `force` is true, because replacing the CA
// invalidates every certificate already handed out. Prints what it wrote.
// Returns true on success.
bool GenerateCertificateSet(const std::string& certDir, unsigned clientCount,
                            const std::string& clientLabel, bool force);

// Signs `clientCount` more labeled client certificates with the existing
// certDir/ca.crt + ca.key. Numbering continues after the highest
// "<clientLabel>-NN.crt" already present. Never overwrites a file. Returns
// true on success.
bool AddClientCertificates(const std::string& certDir, unsigned clientCount,
                           const std::string& clientLabel);

}  // namespace CertTool

#endif  // BSCHUB_EXAMPLE_CERT_TOOL_H
