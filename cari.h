// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_CARI_H
#define BSCHUB_EXAMPLE_CARI_H

// cari.h
// =============================================================================
// CARI files: Certificate Authority Requirements Interchange, ANSI/ASHRAE
// 135-2024 Annex AA.2 (Addendum cs to 135-2020). A CARI file is a zip of a
// strict folder tree with the root folder cert1/:
//
//   cert1/vendor-data, request-notes.txt          optional (request)
//   cert1/response-notes.txt, errors.txt          optional / on errors (response)
//   cert1/device-<instance>/                      one per device
//       router/                                   empty: it routes between SC networks
//       port-<id>/                                one per BACnet/SC port
//           hub/                                  empty: this port is a hub function
//           csr-<name>.pem                        the request (PKCS#10)
//           key-<name>.pem                        optional; the CA ignores it but keeps it
//           opr-<name>.pem                        the signed operational certificate (response)
//   cert1/issuer/iss-1.pem, iss-2.pem             the issuer(s) (response)
//
// This file holds the zip reader/writer (on zlib) and the tree model. The
// signing itself is in cert_tool.cpp. The zip reader is written for input
// from anyone: it checks sizes, entry counts, compression methods and every
// path before anything is extracted, and refuses anything else.
// =============================================================================

#include <stdint.h>

#include <map>
#include <set>
#include <string>
#include <vector>

namespace Cari {

// Limits (AA.2.1.1/AA.2.1.2 for the notes and vendor-data; the rest are this
// hub's own, generous for a site's worth of devices).
static const size_t MAX_ZIP_BYTES = 4 * 1024 * 1024;
static const size_t MAX_ENTRIES = 4096;
static const size_t MAX_TOTAL_UNCOMPRESSED = 16 * 1024 * 1024;
static const size_t MAX_VENDOR_DATA = 1024 * 1024;
static const size_t MAX_NOTES = 10 * 1024;
static const size_t MAX_PEM = 64 * 1024;

// A CARI tree in memory: file path -> contents, and the (possibly empty)
// folders. Paths are relative, '/'-separated, start with "cert1", and have no
// trailing '/'.
struct Tree {
    std::map<std::string, std::string> files;
    std::set<std::string> folders;

    void AddFile(const std::string& path, const std::string& bytes);  // adds the parent folders too
    void AddFolder(const std::string& path);                          // and its parents
    void Remove(const std::string& path);
    bool Has(const std::string& path) const { return files.count(path) != 0; }
};

// One CSR in a request, and where its answer goes.
struct CsrEntry {
    std::string deviceFolder;   // "device-12"
    uint32_t deviceInstance = 0;
    std::string portFolder;     // "port-1"
    std::string name;           // the <name> in csr-<name>.pem
    std::string csrPath;        // "cert1/device-12/port-1/csr-<name>.pem"
    std::string oprPath;        // the matching opr-<name>.pem
    std::string keyPath;        // key-<name>.pem ("" if absent)
    bool isHubPort = false;     // the port folder has hub/
    bool isRouter = false;      // the device folder has router/
};

// --- zip ---------------------------------------------------------------------

// Reads a zip (stored or deflate entries only; no encryption, no zip64).
// Folder entries ("name/") go to `folders`. False with a reason on anything
// malformed or over the limits above.
bool ReadZip(const std::string& zipBytes, Tree* out, std::string* error);

// Writes `tree` as a zip (deflate), folders as their own entries so empty
// ones (hub/, router/) survive.
std::string WriteZip(const Tree& tree);

// --- CARI rules ----------------------------------------------------------------

// Checks every path against AA.2.1 (only the names above, legal characters in
// <id> and <name>, device instances 0..4194302, sizes) and that there is at
// least one device folder with one port folder. `response` also allows the
// response-only names. Each problem is one line in *problems.
bool Validate(const Tree& tree, bool response, std::vector<std::string>* problems);

// Every csr-*.pem in the tree.
std::vector<CsrEntry> ListCsrs(const Tree& tree);

// True if `text` may be a port <id> or a file <name>: printable, non-empty,
// and none of < > : " / \ | ? *.
bool IsValidName(const std::string& text);

// --- disk ------------------------------------------------------------------------

// Writes the tree under baseDir (baseDir/cert1/...), creating folders. Never
// writes outside baseDir. Private keys get owner-only permissions.
bool WriteToDir(const Tree& tree, const std::string& baseDir, std::string* error);

// Reads baseDir/cert1/ back into a tree. False if there is no cert1/.
bool ReadFromDir(const std::string& baseDir, Tree* out, std::string* error);

}  // namespace Cari

#endif  // BSCHUB_EXAMPLE_CARI_H
