// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// cert_store.cpp - see cert_store.h for what this does and why.

#include "cert_store.h"
#include "sc_transport/KeyPassword.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>  // X509_check_ca, X509_PURPOSE_*

#include <stdio.h>
#include <string.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <set>

#if defined(_WIN32)
#include <io.h>       // _commit - flush a file to disk
#include <windows.h>  // MoveFileExA - an atomic replace that works over an existing file
#else
#include <fcntl.h>    // open(O_CREAT | O_EXCL, 0600) - private temp files
#include <unistd.h>   // fsync, close
#endif

namespace fs = std::filesystem;

namespace CertStore {
namespace {

// BACnetErrorCode values the stack honours for AtomicWriteFile / WriteProperty.
const uint32_t ERROR_INVALID_FILE_START_POSITION = 11;
const uint32_t ERROR_FILE_FULL = 128;
const uint32_t ERROR_VALUE_OUT_OF_RANGE = 37;

struct Staged {
    std::string bytes;
    time_t modified = 0;
};

Layout g_layout;
std::map<uint32_t, Staged> g_staged;  // file instance -> staged contents
// Set by ValidateStaged() when the staged operational certificate is for the
// pending key (GENERATE_CSR_FILE) rather than the current one; CommitStaged()
// then swaps the pending key in.
bool g_commitPromotesPendingKey = false;

bool ReadDisk(const std::string& path, std::string* out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return false;
    }
    out->assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

// The file a File object's bytes live in, or "" if it isn't one we manage.
std::string OwnPath(uint32_t fileInstance) {
    auto it = g_layout.paths.find(fileInstance);
    return it == g_layout.paths.end() ? std::string() : it->second;
}

// The File object this one serves instead, while it has no staged copy and
// no file of its own (Issuer Certificate slot 2 serves slot 1 until something
// is written to it), or 0.
uint32_t FallbackInstance(uint32_t fileInstance) {
    if (g_staged.count(fileInstance) != 0) {
        return 0;
    }
    std::error_code ec;
    const std::string path = OwnPath(fileInstance);
    if (path.empty() || fs::exists(path, ec)) {
        return 0;
    }
    auto fb = g_layout.readFallbackInstances.find(fileInstance);
    return fb == g_layout.readFallbackInstances.end() ? 0 : fb->second;
}

// The staged copy of a File object, created from its current contents on the
// first write since the last commit.
Staged* Stage(uint32_t fileInstance) {
    auto it = g_staged.find(fileInstance);
    if (it != g_staged.end()) {
        return &it->second;
    }
    if (g_layout.paths.find(fileInstance) == g_layout.paths.end()) {
        return nullptr;
    }
    Staged s;
    if (!Read(fileInstance, &s.bytes)) {  // a missing file stages as empty
        s.bytes.clear();
    }
    s.modified = time(NULL);
    return &(g_staged[fileInstance] = s);
}

void FreeAll(std::vector<X509*>* certs) {
    for (X509* c : *certs) {
        X509_free(c);
    }
    certs->clear();
}

// Splits a PEM blob into its "-----BEGIN <label>-----" ... "-----END <label>-----"
// blocks. Only blocks labelled `label` and whitespace between them are
// allowed: anything else - a PRIVATE KEY block in a combined cert+key file,
// stray text - is refused, because these files are served to anyone over
// AtomicReadFile exactly as written. An empty or whitespace-only blob yields
// no blocks.
bool SplitPemBlocks(const std::string& pem, const std::string& label, std::vector<std::string>* blocks,
                    std::string* reason) {
    static const char* const kBegin = "-----BEGIN ";
    static const char* const kDashes = "-----";
    size_t pos = 0;
    while (true) {
        const size_t begin = pem.find(kBegin, pos);
        const size_t gapEnd = begin == std::string::npos ? pem.size() : begin;
        if (pem.find_first_not_of(" \t\r\n", pos) < gapEnd) {
            *reason = "has text outside a PEM block";
            return false;
        }
        if (begin == std::string::npos) {
            return true;
        }
        const size_t labelStart = begin + strlen(kBegin);
        const size_t labelEnd = pem.find(kDashes, labelStart);
        if (labelEnd == std::string::npos) {
            *reason = "has an unterminated PEM header";
            return false;
        }
        const std::string found = pem.substr(labelStart, labelEnd - labelStart);
        if (found != label) {
            // The label is the writer's text and ends up in log lines: keep
            // printable ASCII only.
            std::string shown;
            for (const char c : found.substr(0, 40)) {
                shown += (c >= 0x20 && c < 0x7f) ? c : '?';
            }
            *reason = "holds a \"" + shown + "\" PEM block (only " + label + " is allowed here)";
            return false;
        }
        const std::string endMarker = "-----END " + label + kDashes;
        const size_t end = pem.find(endMarker, labelEnd);
        if (end == std::string::npos) {
            *reason = "has a " + label + " block with no END line";
            return false;
        }
        pos = end + endMarker.size();
        blocks->push_back(pem.substr(begin, pos - begin));
    }
}

// Every certificate in a PEM blob. An empty or whitespace-only blob yields
// none; anything else that isn't only PEM certificates is an error.
bool ParseCertificates(const std::string& pem, std::vector<X509*>* out, std::string* reason) {
    std::vector<std::string> blocks;
    if (!SplitPemBlocks(pem, "CERTIFICATE", &blocks, reason)) {
        return false;
    }
    if (blocks.empty()) {
        if (pem.find_first_not_of(" \t\r\n") == std::string::npos) {
            return true;  // empty
        }
        *reason = "not a PEM certificate";
        return false;
    }
    for (const std::string& block : blocks) {
        BIO* bio = BIO_new_mem_buf(block.data(), (int)block.size());
        X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        ERR_clear_error();
        if (cert == NULL) {
            FreeAll(out);
            *reason = "holds a CERTIFICATE block that doesn't parse";
            return false;
        }
        out->push_back(cert);
    }
    return true;
}

// True if `leaf` verifies for `purpose` against the issuer certificates.
// Each issuer is tried on its own first: two issuers can share a subject name
// (two lab CAs, or a renewed CA), and a certificate without an Authority Key
// Identifier then can't tell them apart - verifying against both at once lets
// OpenSSL pick the wrong one and report a signature failure. Then all of them
// together, which is what TLS trusts (trusted-issuers.pem): a root in one slot
// and an intermediate in the other only verifies that way.
bool ChainsToIssuers(X509* leaf, const std::vector<X509*>& intermediates, const std::vector<X509*>& issuers,
                     int purpose, std::string* why) {
    STACK_OF(X509)* chain = sk_X509_new_null();
    for (X509* c : intermediates) {
        sk_X509_push(chain, c);  // intermediates in the operational certificate's own file
    }
    *why = "no issuer certificate";
    bool chained = false;
    for (size_t attempt = 0; !chained && attempt <= issuers.size(); ++attempt) {
        if (attempt == issuers.size() && issuers.size() < 2) {
            break;  // "all together" is the same as the single try
        }
        X509_STORE* store = X509_STORE_new();
        for (size_t i = 0; i < issuers.size(); ++i) {
            if (attempt == issuers.size() || i == attempt) {
                X509_STORE_add_cert(store, issuers[i]);
            }
        }
        X509_STORE_CTX* ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, leaf, chain);
        X509_STORE_CTX_set_purpose(ctx, purpose);
        if (X509_verify_cert(ctx) == 1) {
            chained = true;
        } else {
            *why = X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
        }
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
    }
    sk_X509_free(chain);
    ERR_clear_error();
    return chained;
}

// A file's contents as they would be after commit.
std::string Effective(uint32_t fileInstance) {
    std::string bytes;
    if (!Read(fileInstance, &bytes)) {
        bytes.clear();
    }
    return bytes;
}

// A PEM private key from disk, or nullptr. The caller frees it.
EVP_PKEY* LoadKey(const std::string& path) {
    std::string keyPem;
    if (path.empty() || !ReadDisk(path, &keyPem)) {
        return nullptr;
    }
    BIO* bio = BIO_new_mem_buf(keyPem.data(), (int)keyPem.size());
    // A password-protected key uses the password asked for once at start-up; OpenSSL must not prompt.
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, NULL, CASSc::KeyPassword::PemCallback, NULL);
    BIO_free(bio);
    ERR_clear_error();
    return key;
}

// Writes `bytes` to "<path>.tmp" and flushes it to disk. A private file (a
// key) is created owner read/write only from the start on POSIX, so the key
// is never readable by others, even for a moment or if the rename fails. On
// Windows the file inherits the folder's ACL.
bool WriteTempFile(const std::string& path, const std::string& bytes, bool privateFile, std::string* reason) {
    const std::string tmp = path + ".tmp";
    std::remove(tmp.c_str());  // a leftover from an interrupted write
#if defined(_WIN32)
    (void)privateFile;
    FILE* f = NULL;
    if (fopen_s(&f, tmp.c_str(), "wb") != 0) {
        f = NULL;
    }
#else
    const int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, privateFile ? 0600 : 0644);
    FILE* f = fd >= 0 ? fdopen(fd, "wb") : NULL;
    if (f == NULL && fd >= 0) {
        close(fd);
    }
#endif
    bool ok = f != NULL && fwrite(bytes.data(), 1, bytes.size(), f) == bytes.size() && fflush(f) == 0;
#if defined(_WIN32)
    ok = ok && _commit(_fileno(f)) == 0;
#else
    ok = ok && fsync(fileno(f)) == 0;
#endif
    if (f != NULL && fclose(f) != 0) {
        ok = false;
    }
    if (!ok) {
        std::remove(tmp.c_str());
        *reason = "could not write \"" + tmp + "\"";
    }
    return ok;
}

// Replaces `path` with "<path>.tmp" (from WriteTempFile) in one step.
bool ReplaceWithTemp(const std::string& path, std::string* reason) {
    const std::string tmp = path + ".tmp";
#if defined(_WIN32)
    const bool ok = MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    const bool ok = std::rename(tmp.c_str(), path.c_str()) == 0;
#endif
    if (!ok) {
        *reason = "could not replace \"" + path + "\"";
    }
    return ok;
}

bool AtomicWriteFileToDisk(const std::string& path, const std::string& bytes, std::string* reason,
                           bool privateFile = false) {
    if (!WriteTempFile(path, bytes, privateFile, reason)) {
        return false;
    }
    if (!ReplaceWithTemp(path, reason)) {
        std::remove((path + ".tmp").c_str());
        return false;
    }
    return true;
}

// Moves the pending key (GENERATE_CSR_FILE) over the hub's key.
bool PromotePendingKey(std::string* reason) {
#if defined(_WIN32)
    const bool moved = MoveFileExA(g_layout.pendingPrivateKeyPath.c_str(), g_layout.privateKeyPath.c_str(),
                                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    const bool moved = std::rename(g_layout.pendingPrivateKeyPath.c_str(), g_layout.privateKeyPath.c_str()) == 0;
#endif
    if (!moved) {
        *reason = "could not replace \"" + g_layout.privateKeyPath + "\" with the pending key \"" +
                  g_layout.pendingPrivateKeyPath + "\"";
    }
    return moved;
}

}  // namespace

void SetLayout(const Layout& layout) {
    g_layout = layout;
    g_staged.clear();
}

bool Read(uint32_t fileInstance, std::string* bytes) {
    auto it = g_staged.find(fileInstance);
    if (it != g_staged.end()) {
        *bytes = it->second.bytes;
        return true;
    }
    const uint32_t fallback = FallbackInstance(fileInstance);
    if (fallback != 0) {
        return Read(fallback, bytes);
    }
    const std::string path = OwnPath(fileInstance);
    return !path.empty() && ReadDisk(path, bytes);
}

bool Stat(uint32_t fileInstance, long* size, time_t* mtime) {
    auto it = g_staged.find(fileInstance);
    if (it != g_staged.end()) {
        *size = (long)it->second.bytes.size();
        *mtime = it->second.modified;
        return true;
    }
    const uint32_t fallback = FallbackInstance(fileInstance);
    if (fallback != 0) {
        return Stat(fallback, size, mtime);
    }
    const std::string path = OwnPath(fileInstance);
    std::error_code ec;
    if (path.empty() || !fs::exists(path, ec)) {
        return false;
    }
    *size = (long)fs::file_size(path, ec);
    const auto ftime = fs::last_write_time(path, ec);
    // file_time_type -> time_t: shift by "now" in both clocks (portable C++17).
    const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
    *mtime = std::chrono::system_clock::to_time_t(sctp);
    return !ec;
}

bool Write(uint32_t fileInstance, int32_t fileStart, const uint8_t* data, uint32_t length,
           int32_t* ackFileStart, uint32_t* errorCode) {
    Staged* s = Stage(fileInstance);
    if (s == nullptr) {
        *errorCode = ERROR_INVALID_FILE_START_POSITION;  // not a certificate file we manage
        return false;
    }
    // -1 = append (cl. 14.2.1.3.1); the ACK must report where the write began.
    // Any other negative start is invalid.
    if (fileStart < -1) {
        *errorCode = ERROR_INVALID_FILE_START_POSITION;
        return false;
    }
    const size_t start = (fileStart == -1) ? s->bytes.size() : (size_t)fileStart;
    if (start > s->bytes.size()) {
        *errorCode = ERROR_INVALID_FILE_START_POSITION;  // no holes
        return false;
    }
    if (start + length > MAX_FILE_BYTES) {
        *errorCode = ERROR_FILE_FULL;
        return false;
    }
    if (start + length > s->bytes.size()) {
        s->bytes.resize(start + length);
    }
    memcpy(&s->bytes[start], data, length);
    s->modified = time(NULL);
    *ackFileStart = (int32_t)start;
    return true;
}

bool Resize(uint32_t fileInstance, uint32_t newSize, uint32_t* errorCode) {
    if (newSize > MAX_FILE_BYTES) {
        *errorCode = ERROR_VALUE_OUT_OF_RANGE;
        return false;
    }
    Staged* s = Stage(fileInstance);
    if (s == nullptr) {
        return false;  // not ours - the stack answers write-access-denied
    }
    s->bytes.resize(newSize, '\0');  // truncate, or extend with zero octets
    s->modified = time(NULL);
    return true;
}

bool HasStagedChanges() {
    return !g_staged.empty();
}

bool ValidateStaged(std::string* reason) {
    // Issuers, as they would be after commit.
    std::vector<X509*> issuers;
    for (uint32_t inst : g_layout.issuerInstances) {
        std::string why;
        if (!ParseCertificates(Effective(inst), &issuers, &why)) {
            FreeAll(&issuers);
            *reason = "File " + std::to_string(inst) + " (issuer certificate): " + why;
            return false;
        }
    }
    if (issuers.empty()) {
        *reason = "no issuer certificate - both Issuer_Certificate_Files would be empty";
        return false;
    }

    // The operational certificate (the first certificate in its file).
    std::vector<X509*> operational;
    std::string why;
    if (!ParseCertificates(Effective(g_layout.operationalInstance), &operational, &why) ||
        operational.empty()) {
        FreeAll(&issuers);
        FreeAll(&operational);
        *reason = "File " + std::to_string(g_layout.operationalInstance) + " (operational certificate): " +
                  (why.empty() ? std::string("empty") : why);
        return false;
    }

    bool ok = true;
    // It must belong to this hub's private key, or to the pending key from
    // GENERATE_CSR_FILE: a new operational certificate is issued for the key
    // behind the Certificate Signing Request File object.
    g_commitPromotesPendingKey = false;
    EVP_PKEY* key = LoadKey(g_layout.privateKeyPath);
    EVP_PKEY* pendingKey = LoadKey(g_layout.pendingPrivateKeyPath);
    if (key != nullptr && X509_check_private_key(operational[0], key) == 1) {
        // The current key: nothing else changes.
    } else if (pendingKey != nullptr && X509_check_private_key(operational[0], pendingKey) == 1) {
        g_commitPromotesPendingKey = true;
    } else if (key == nullptr) {
        *reason = "could not read this hub's private key \"" + g_layout.privateKeyPath + "\"";
        ok = false;
    } else {
        *reason = "the operational certificate does not match this hub's private key (sign the "
                  "Certificate Signing Request File instead)";
        ok = false;
    }
    EVP_PKEY_free(key);
    EVP_PKEY_free(pendingKey);
    ERR_clear_error();

    // It must be an end-entity certificate: a CA certificate as the hub's own
    // would be refused by every peer.
    if (ok && X509_check_ca(operational[0]) != 0) {
        *reason = "the operational certificate is a CA certificate (basicConstraints CA:TRUE or keyCertSign), "
                  "not the hub's own";
        ok = false;
    }

    // ...and chain to the issuers, for both TLS roles the hub plays (server to
    // connecting devices, client when it dials another hub), or peers refuse it.
    if (ok) {
        std::vector<X509*> intermediates(operational.begin() + 1, operational.end());
        const char* const roles[2] = {"TLS server", "TLS client"};
        const int purposes[2] = {X509_PURPOSE_SSL_SERVER, X509_PURPOSE_SSL_CLIENT};
        for (int i = 0; ok && i < 2; ++i) {
            std::string chainError;
            if (!ChainsToIssuers(operational[0], intermediates, issuers, purposes[i], &chainError)) {
                *reason = "the operational certificate does not verify as a " + std::string(roles[i]) +
                          " certificate against the issuer certificates (" + chainError + ")";
                ok = false;
            }
        }
    }

    FreeAll(&issuers);
    FreeAll(&operational);
    return ok;
}

bool CommitStaged(std::string* reason) {
    // All or nothing, as far as the filesystem allows: every file is written
    // and flushed to a temp file first (a failure there changes nothing and
    // keeps the stage), then each is renamed into place.
    std::vector<std::string> paths;
    for (const auto& kv : g_staged) {
        const auto path = g_layout.paths.find(kv.first);
        if (path == g_layout.paths.end() || !WriteTempFile(path->second, kv.second.bytes, false, reason)) {
            for (const std::string& written : paths) {
                std::remove((written + ".tmp").c_str());
            }
            return false;
        }
        paths.push_back(path->second);
    }
    for (const std::string& path : paths) {
        if (!ReplaceWithTemp(path, reason)) {
            return false;  // keeps the stage, so activating again retries
        }
    }
    g_staged.clear();
    if (g_commitPromotesPendingKey) {
        // The new certificate is on disk; its key goes in next, so TLS (reloaded
        // after this returns) loads a matching pair. If this fails (or the
        // process stops here), ReconcilePendingKey() at the next start sees a
        // certificate for the pending key and finishes the swap.
        if (!PromotePendingKey(reason)) {
            return false;
        }
        g_commitPromotesPendingKey = false;
    }
    return true;
}

bool ReconcilePendingKey(std::string* message) {
    message->clear();
    std::error_code ec;
    if (g_layout.pendingPrivateKeyPath.empty() || !fs::exists(g_layout.pendingPrivateKeyPath, ec)) {
        return true;
    }
    std::vector<X509*> operational;
    std::string why;
    std::string bytes;
    const auto opPath = g_layout.paths.find(g_layout.operationalInstance);
    if (opPath == g_layout.paths.end() || !ReadDisk(opPath->second, &bytes) ||
        !ParseCertificates(bytes, &operational, &why) || operational.empty()) {
        FreeAll(&operational);
        return true;  // nothing to compare with - leave both keys alone
    }
    EVP_PKEY* key = LoadKey(g_layout.privateKeyPath);
    EVP_PKEY* pendingKey = LoadKey(g_layout.pendingPrivateKeyPath);
    const bool certForCurrent = key != nullptr && X509_check_private_key(operational[0], key) == 1;
    const bool certForPending = pendingKey != nullptr && X509_check_private_key(operational[0], pendingKey) == 1;
    EVP_PKEY_free(key);
    EVP_PKEY_free(pendingKey);
    FreeAll(&operational);
    ERR_clear_error();
    if (certForCurrent || !certForPending) {
        return true;  // the usual case: a CSR is out for signing, or the pending key is unrelated
    }
    if (!PromotePendingKey(message)) {
        return false;
    }
    *message = "the operational certificate is for the pending key from GENERATE_CSR_FILE (an earlier "
               "activation didn't finish): \"" + g_layout.pendingPrivateKeyPath + "\" now replaces \"" +
               g_layout.privateKeyPath + "\"";
    return true;
}

void DiscardStaged() {
    g_staged.clear();
    g_commitPromotesPendingKey = false;
}

bool GenerateKeyAndCsr(std::string* reason) {
    if (!g_staged.empty()) {
        *reason = "certificate writes are staged - activate or discard them first";
        return false;
    }
    const auto csrPath = g_layout.paths.find(g_layout.csrInstance);
    if (csrPath == g_layout.paths.end() || g_layout.pendingPrivateKeyPath.empty()) {
        *reason = "no Certificate Signing Request file configured";
        return false;
    }
    // The subject stays the same: the new certificate identifies the same hub.
    std::vector<X509*> operational;
    std::string why;
    if (!ParseCertificates(Effective(g_layout.operationalInstance), &operational, &why) || operational.empty()) {
        FreeAll(&operational);
        *reason = "could not read the current operational certificate for its subject" +
                  (why.empty() ? std::string() : ": " + why);
        return false;
    }

    EVP_PKEY* key = EVP_EC_gen("P-256");
    X509_REQ* request = X509_REQ_new();
    bool ok = key != nullptr && request != nullptr &&
              X509_REQ_set_version(request, 0) == 1 &&
              X509_REQ_set_subject_name(request, X509_get_subject_name(operational[0])) == 1 &&
              X509_REQ_set_pubkey(request, key) == 1 &&
              X509_REQ_sign(request, key, EVP_sha256()) > 0;
    FreeAll(&operational);
    std::string keyPem;
    std::string csrPem;
    if (ok) {
        BIO* keyBio = BIO_new(BIO_s_mem());
        BIO* csrBio = BIO_new(BIO_s_mem());
        ok = PEM_write_bio_PrivateKey(keyBio, key, NULL, NULL, 0, NULL, NULL) == 1 &&
             PEM_write_bio_X509_REQ(csrBio, request) == 1;
        char* p = nullptr;
        long n = BIO_get_mem_data(keyBio, &p);
        keyPem.assign(p, (size_t)n);
        n = BIO_get_mem_data(csrBio, &p);
        csrPem.assign(p, (size_t)n);
        BIO_free(keyBio);
        BIO_free(csrBio);
    }
    X509_REQ_free(request);
    EVP_PKEY_free(key);
    ERR_clear_error();
    if (!ok) {
        *reason = "OpenSSL could not generate the key pair or the request";
        return false;
    }
    // Both written and flushed before either replaces anything, so a failed
    // write leaves the old pending key and its CSR matching each other. Then
    // the key first: a CSR on disk without its key could never be used.
    if (!WriteTempFile(g_layout.pendingPrivateKeyPath, keyPem, true, reason)) {
        return false;
    }
    if (!WriteTempFile(csrPath->second, csrPem, false, reason)) {
        std::remove((g_layout.pendingPrivateKeyPath + ".tmp").c_str());
        return false;
    }
    if (!ReplaceWithTemp(g_layout.pendingPrivateKeyPath, reason)) {
        std::remove((g_layout.pendingPrivateKeyPath + ".tmp").c_str());
        std::remove((csrPath->second + ".tmp").c_str());
        return false;
    }
    return ReplaceWithTemp(csrPath->second, reason);
}

bool WriteTrustedIssuerBundle(const std::string& bundlePath, std::string* reason) {
    std::string bundle;
    std::set<std::string> seen;
    for (uint32_t inst : g_layout.issuerInstances) {
        std::vector<X509*> certs;
        std::string why;
        std::string bytes;
        if (Read(inst, &bytes) && ParseCertificates(bytes, &certs, &why)) {
            for (X509* c : certs) {
                BIO* out = BIO_new(BIO_s_mem());
                PEM_write_bio_X509(out, c);
                char* p = nullptr;
                const long n = BIO_get_mem_data(out, &p);
                const std::string pem(p, (size_t)n);
                BIO_free(out);
                if (seen.insert(pem).second) {
                    bundle += pem;
                }
            }
        }
        FreeAll(&certs);
    }
    if (bundle.empty()) {
        *reason = "no issuer certificate to trust";
        return false;
    }
    return AtomicWriteFileToDisk(bundlePath, bundle, reason);
}

}  // namespace CertStore
