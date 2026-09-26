// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// cert_store.cpp - see cert_store.h for what this does and why.

#include "cert_store.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <stdio.h>
#include <string.h>

#include <chrono>
#include <filesystem>
#include <set>

#if defined(_WIN32)
#include <windows.h>  // MoveFileExA - an atomic replace that works over an existing file
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

bool ReadDisk(const std::string& path, std::string* out) {
    FILE* f = fopen(path.c_str(), "rb");
    if (f == NULL) {
        return false;
    }
    out->clear();
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        out->append(buf, n);
    }
    fclose(f);
    return true;
}

// The path a File object's bytes are read from right now: its own file, or
// its fallback until its own file exists (Issuer Certificate Slot 2 serves
// slot 1's file until something is written to it).
std::string ReadPath(uint32_t fileInstance) {
    auto it = g_layout.paths.find(fileInstance);
    if (it == g_layout.paths.end()) {
        return std::string();
    }
    std::error_code ec;
    if (!fs::exists(it->second, ec)) {
        auto fb = g_layout.readFallbacks.find(fileInstance);
        if (fb != g_layout.readFallbacks.end()) {
            return fb->second;
        }
    }
    return it->second;
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
    ReadDisk(ReadPath(fileInstance), &s.bytes);  // a missing file stages as empty
    s.modified = time(NULL);
    return &(g_staged[fileInstance] = s);
}

// Every certificate in a PEM blob. An empty or whitespace-only blob yields
// none; anything else that doesn't parse completely is an error.
bool ParseCertificates(const std::string& pem, std::vector<X509*>* out, std::string* reason) {
    if (pem.find_first_not_of(" \t\r\n") == std::string::npos) {
        return true;  // empty
    }
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    X509* cert;
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        out->push_back(cert);
    }
    ERR_clear_error();  // the read loop always ends with a harmless "no start line"
    BIO_free(bio);
    if (out->empty()) {
        *reason = "not a PEM certificate";
        return false;
    }
    return true;
}

void FreeAll(std::vector<X509*>* certs) {
    for (X509* c : *certs) {
        X509_free(c);
    }
    certs->clear();
}

// A file's contents as they would be after commit.
std::string Effective(uint32_t fileInstance) {
    std::string bytes;
    if (!Read(fileInstance, &bytes)) {
        bytes.clear();
    }
    return bytes;
}

bool AtomicWriteFileToDisk(const std::string& path, const std::string& bytes, std::string* reason) {
    const std::string tmp = path + ".tmp";
    FILE* f = fopen(tmp.c_str(), "wb");
    if (f == NULL || fwrite(bytes.data(), 1, bytes.size(), f) != bytes.size()) {
        if (f != NULL) {
            fclose(f);
        }
        *reason = "could not write \"" + tmp + "\"";
        return false;
    }
    fclose(f);
#if defined(_WIN32)
    const bool ok = MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING) != 0;
#else
    const bool ok = std::rename(tmp.c_str(), path.c_str()) == 0;
#endif
    if (!ok) {
        *reason = "could not replace \"" + path + "\"";
        return false;
    }
    return true;
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
    const std::string path = ReadPath(fileInstance);
    return !path.empty() && ReadDisk(path, bytes);
}

bool Stat(uint32_t fileInstance, long* size, time_t* mtime) {
    auto it = g_staged.find(fileInstance);
    if (it != g_staged.end()) {
        *size = (long)it->second.bytes.size();
        *mtime = it->second.modified;
        return true;
    }
    const std::string path = ReadPath(fileInstance);
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
    const size_t start = (fileStart < 0) ? s->bytes.size() : (size_t)fileStart;
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
    // It must belong to this hub's private key: GENERATE_CSR_FILE isn't
    // available (issue #10), so a new operational certificate has to be
    // issued for the key behind the Certificate Signing Request File object.
    std::string keyPem;
    EVP_PKEY* key = nullptr;
    if (ReadDisk(g_layout.privateKeyPath, &keyPem)) {
        BIO* bio = BIO_new_mem_buf(keyPem.data(), (int)keyPem.size());
        key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    if (key == nullptr) {
        *reason = "could not read this hub's private key \"" + g_layout.privateKeyPath + "\"";
        ok = false;
    } else if (X509_check_private_key(operational[0], key) != 1) {
        *reason = "the operational certificate does not match this hub's private key (sign the "
                  "Certificate Signing Request File instead)";
        ok = false;
    }
    EVP_PKEY_free(key);
    ERR_clear_error();

    // ...and chain to one of the issuers, or no peer would accept this hub.
    // Each issuer is tried on its own: two issuers can share a subject name
    // (two lab CAs, or a renewed CA), and a certificate without an Authority
    // Key Identifier then can't tell them apart - verifying against both at
    // once lets OpenSSL pick the wrong one and report a signature failure.
    if (ok) {
        STACK_OF(X509)* chain = sk_X509_new_null();
        for (size_t i = 1; i < operational.size(); ++i) {
            sk_X509_push(chain, operational[i]);  // intermediates in the same file
        }
        bool chained = false;
        std::string lastError = "no issuer certificate";
        for (X509* ca : issuers) {
            X509_STORE* store = X509_STORE_new();
            X509_STORE_add_cert(store, ca);
            X509_STORE_CTX* ctx = X509_STORE_CTX_new();
            X509_STORE_CTX_init(ctx, store, operational[0], chain);
            if (X509_verify_cert(ctx) == 1) {
                chained = true;
            } else {
                lastError = X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
            }
            X509_STORE_CTX_free(ctx);
            X509_STORE_free(store);
            if (chained) {
                break;
            }
        }
        sk_X509_free(chain);
        ERR_clear_error();
        if (!chained) {
            *reason = "the operational certificate does not chain to an issuer certificate (" + lastError + ")";
            ok = false;
        }
    }

    FreeAll(&issuers);
    FreeAll(&operational);
    return ok;
}

bool CommitStaged(std::string* reason) {
    for (const auto& kv : g_staged) {
        const auto path = g_layout.paths.find(kv.first);
        if (path == g_layout.paths.end() || !AtomicWriteFileToDisk(path->second, kv.second.bytes, reason)) {
            return false;
        }
    }
    g_staged.clear();
    return true;
}

void DiscardStaged() {
    g_staged.clear();
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
