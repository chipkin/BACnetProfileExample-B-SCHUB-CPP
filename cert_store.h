// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_CERT_STORE_H
#define BSCHUB_EXAMPLE_CERT_STORE_H

// cert_store.h
// =============================================================================
// The certificate File objects' contents, and the device-B side of the
// BACnet/SC certificate procedures (ANSI/ASHRAE 135-2024 clause 19.8.3):
//
//   1. A client (e.g. the CAS BACnet Explorer) writes File_Size = 0 and then
//      AtomicWriteFile's a new certificate into a certificate File object.
//   2. Those writes are STAGED here - kept in memory, served back by
//      AtomicReadFile/File_Size so the client can check what it wrote, but not
//      written to disk and not used by TLS. The stack raises the SC Network
//      Port's Changes_Pending (cl. 12.56.100) on its own.
//   3. ReinitializeDevice ACTIVATE_CHANGES (or WARMSTART) makes them live:
//      main.cpp's ReinitializeDevice callback calls ValidateStaged() - which
//      refuses a set that would lock the hub out (a certificate that doesn't
//      parse, an operational certificate that doesn't match this hub's private
//      key or doesn't chain to an issuer) - then CommitStaged(), which writes
//      each file atomically (temp file + rename), then main.cpp reloads TLS.
//
// Why stage instead of writing through to disk: the procedure writes a file in
// several steps (truncate, then one or more AtomicWriteFile chunks). If those
// hit the disk directly, a hub connection that dropped and re-dialled halfway
// through would load a half-written certificate.
//
// The private key never passes through here, and no File object serves it.
// =============================================================================

#include <stdint.h>
#include <time.h>

#include <map>
#include <string>
#include <vector>

namespace CertStore {

// Largest certificate file a client may write (a PEM chain is a few KiB).
static const uint32_t MAX_FILE_BYTES = 64 * 1024;

// Where each certificate File object's bytes live on disk. main.cpp fills this
// in from --sc-cert-dir (see cert_tool.h for the file names).
struct Layout {
    std::map<uint32_t, std::string> paths;  // File object instance -> file on disk
    std::map<uint32_t, std::string> readFallbacks;  // instance -> file served until its own exists
    uint32_t operationalInstance = 0;        // Operational_Certificate_File
    std::vector<uint32_t> issuerInstances;   // Issuer_Certificate_Files
    std::string privateKeyPath;              // the operational certificate's key
};

void SetLayout(const Layout& layout);

// The bytes a File object currently holds: the staged copy if there is one,
// otherwise the file on disk. False if the instance is unknown or unreadable.
bool Read(uint32_t fileInstance, std::string* bytes);

// Size and modification time, of the staged copy or the file on disk.
bool Stat(uint32_t fileInstance, long* size, time_t* mtime);

// AtomicWriteFile. fileStart -1 means append. On failure *errorCode is one of
// the two codes the stack honours for this service: 11 (INVALID_FILE_START_
// POSITION) or 128 (FILE_FULL).
bool Write(uint32_t fileInstance, int32_t fileStart, const uint8_t* data, uint32_t length,
           int32_t* ackFileStart, uint32_t* errorCode);

// WriteProperty File_Size: truncates, or extends with zero octets (cl. 12.13.6).
bool Resize(uint32_t fileInstance, uint32_t newSize, uint32_t* errorCode);

bool HasStagedChanges();

// Checks the files as they WOULD be after CommitStaged(). Returns false with a
// human-readable reason if activating them would leave the hub unable to run
// BACnet/SC: every non-empty certificate file must parse as PEM certificates,
// at least one issuer must be present, and the operational certificate must
// match the private key and chain to one of the issuers.
bool ValidateStaged(std::string* reason);

// Writes every staged file to disk (atomically) and clears the stage.
bool CommitStaged(std::string* reason);

// Throws away the staged writes.
void DiscardStaged();

// Stages `bytes` as the whole new content of a writable certificate File
// object - the same as WriteProperty File_Size = 0 followed by one
// AtomicWriteFile. Used by the HTTP upload (issue #25), which then validates
// and commits the set exactly like ReinitializeDevice does.
bool StageWholeFile(uint32_t fileInstance, const std::string& bytes, uint32_t* errorCode);

// Replaces the Certificate Signing Request file (read-only over BACnet) after
// checking that `pem` is one PEM certificate request, correctly self-signed,
// for this hub's private key. Written atomically. False with a reason if not.
bool InstallCertificateSigningRequest(uint32_t fileInstance, const std::string& pem, std::string* reason);

// Writes a PEM bundle of every issuer certificate (both Issuer_Certificate_Files
// slots, duplicates removed) to `bundlePath`, for TLS to trust. Returns false
// if there is no issuer certificate at all.
bool WriteTrustedIssuerBundle(const std::string& bundlePath, std::string* reason);

}  // namespace CertStore

#endif  // BSCHUB_EXAMPLE_CERT_STORE_H
