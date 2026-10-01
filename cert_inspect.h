// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_CERT_INSPECT_H
#define BSCHUB_EXAMPLE_CERT_INSPECT_H

// cert_inspect.h
// =============================================================================
// The set-up guide's file inspector (issue #72): what is this file, what is in
// it, and will it work with this hub?
//
// Takes any upload - a PEM file with one or more blocks (certificates, CSRs,
// keys, a CRL), DER, a PKCS#12 (.pfx) with an empty password, or a CARI zip -
// and returns JSON with one item per thing found:
//
//   {"detected": "...", "summary": "...",
//    "items": [{"kind": "certificate", "label": "...",
//               "fields": [{"name": "Subject", "value": "..."}, ...],
//               "checks": [{"name": "...", "status": "pass|warn|fail|info",
//                           "detail": "...", "fix": "..."}, ...]}],
//    "cari": {...}}                                    (for a CARI zip)
//
// Every field of a certificate is listed (subject, issuer, serial, validity,
// key, signature algorithm, fingerprints, every extension). The checks are
// the ones a device or the hub will make, each with what to do when it fails:
// signed by this hub's issuer, valid now, key usage / extended key usage, key
// strength, not a CA, not revoked, key matches certificate, CSR signature.
// Nothing is stored. A private key is only used to check it matches.
// =============================================================================

#include <string>

#include "cert_layout.h"

namespace CertInspect {

// The JSON described above. `fileName` (may be empty) only helps the summary.
std::string InspectJson(const std::string& bytes, const std::string& fileName,
                        const CertLayout::HubCertPaths& paths);

// The same as plain text, for --inspect <file> on the command line. Sets
// *anyFailure if a check failed.
std::string InspectText(const std::string& bytes, const std::string& fileName, const CertLayout::HubCertPaths& paths,
                        bool* anyFailure);

// The fields and checks of one PEM certificate file on disk (the hub's own,
// an issuer), as one "items" entry - for GET /api/setup/info.
std::string CertificateFileJson(const std::string& path, const std::string& label, bool isHubCertificate,
                                const CertLayout::HubCertPaths& paths);

}  // namespace CertInspect

#endif  // BSCHUB_EXAMPLE_CERT_INSPECT_H
