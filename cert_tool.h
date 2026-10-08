// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_CERT_TOOL_H
#define BSCHUB_EXAMPLE_CERT_TOOL_H

// cert_tool.h
// =============================================================================
// The hub's OWN certificate, in the CARI format (ANSI/ASHRAE 135-2024 Annex
// AA.2; see cari.h and cert_layout.h). The hub never signs certificates:
// a Certificate Authority does (the Chipkin BACnet SC Certificate Authority,
// BACnet International's BACCARI, or your own CARI-compatible CA).
//
//   at start-up             EnsureHubRequest(): if <cert-dir>/hub-cari-request.zip
//                           (the hub's CARI request - its CSR only, never the
//                           key - to send to the CA) doesn't exist, make it.
//                           An existing one is never overwritten. A hub with no
//                           key at all also gets a new private key and CSR
//                           (cert1/device-<n>/port-2/{key,csr}-hub.pem); an
//                           existing key is never replaced.
//   --import-cari <zip>     Install the CA's CARI response: the hub's
//                           certificate (opr-hub.pem) and the issuer
//                           certificate(s), after checking the certificate is
//                           for this hub's CSR and is signed by an issuer in
//                           the zip.
//
// The CSR asks for subjectAltName entries for localhost, 127.0.0.1, this
// computer's host name and the host of the hub URI devices dial (main.cpp
// passes this machine's IPv4 address and --sc-port).
//
// Keys are ECDSA P-256 and CSRs are signed with SHA-256.
// =============================================================================

#include <stdint.h>

#include <string>
#include <vector>

#include "cari.h"
#include "cert_layout.h"

namespace CertTool {

// <cert-dir>/hub-cari-request.zip, written at start-up by EnsureHubRequest().
static const char* const HUB_REQUEST_ZIP = "hub-cari-request.zip";

// --- the certificate request, at start-up ------------------------------------------

enum class RequestResult { Created, AlreadyExists, Failed };

// Makes <cert-dir>/hub-cari-request.zip if it doesn't exist; never overwrites
// it. From the CSR on disk when the hub has a key; with no key at all (no
// key-hub.pem and no pending key), first a new key and CSR. Never replaces a
// private key: a key without a CSR is a Failed result, not a new key.
// *message is one line for the log, naming the zip's full path.
RequestResult EnsureHubRequest(const std::string& certDir, uint32_t hubDeviceInstance, const std::string& subjectCn,
                               const std::string& hubUri, std::string* message);

// --- command-line mode (prints what it does; returns true on success) -------------

bool ImportCariResponse(const std::string& certDir, uint32_t hubDeviceInstance, const std::string& zipPath);

// --- building blocks -------------------------------------------------------------

// The CARI request for this hub's existing CSR (csr-hub.pem; never the key),
// as zip bytes. False (with *error) if the hub has no CSR yet.
bool HubRequestZip(const CertLayout::HubCertPaths& paths, std::string* zipBytes, std::string* error);

// What a CARI response holds for this hub, checked but not yet installed.
struct ResponseFiles {
    std::string operationalCertificate;  // PEM: the hub's new certificate (File 1)
    std::vector<std::string> issuers;    // PEM: 1 or 2 issuer certificates (Files 3, 4)
    std::string source;                  // where the certificate was in the zip
    std::string subject;
    std::string issuerSubject;
    std::string notAfter;
    std::string fingerprint;             // SHA-256 of the certificate
};

// Reads a CARI response zip and checks it is for THIS hub: its certificate's
// public key matches the hub's CSR (so a password-protected key is never
// needed), and one of the zip's issuer certificates signed it. Writes nothing.
bool ReadCariResponse(const CertLayout::HubCertPaths& paths, const std::string& zipBytes, ResponseFiles* out,
                      std::string* error);

}  // namespace CertTool

#endif  // BSCHUB_EXAMPLE_CERT_TOOL_H
