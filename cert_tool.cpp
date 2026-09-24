// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// cert_tool.cpp - see cert_tool.h for what this does and why.

#include "cert_tool.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <time.h>

#include <filesystem>
#include <memory>
#include <regex>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>  // gethostname()
#else
#include <unistd.h>    // gethostname()
#endif

namespace fs = std::filesystem;

namespace CertTool {
namespace {

// Same profile as scripts/generate-test-certs.cmake.
const long CA_VALID_DAYS = 3650;
const long LEAF_VALID_DAYS = 825;
const char* const ORGANIZATION = "Chipkin Automation Systems (lab test)";
const char* const CA_COMMON_NAME = "Chipkin Example B-SCHUB Lab CA";
const char* const CN_PREFIX = "Chipkin Example B-SCHUB ";  // + label
const char* const HUB_LABEL = "hub";
const char* const MANIFEST_FILE = "certificates.txt";

// RAII owners for the OpenSSL objects used here.
struct PkeyFree { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct X509Free { void operator()(X509* p) const { X509_free(p); } };
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;
using X509Ptr = std::unique_ptr<X509, X509Free>;

void PrintOpenSslError(const char* what) {
    fprintf(stderr, "Error: %s", what);
    unsigned long e = ERR_get_error();
    if (e != 0) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        fprintf(stderr, " (%s)", buf);
    }
    fprintf(stderr, "\n");
}

// A certificate plus its key, as generated or loaded from disk.
struct Credential {
    PkeyPtr key;
    X509Ptr cert;
};

enum class Role { Ca, Hub, Client };

PkeyPtr NewP256Key() {
    PkeyPtr key(EVP_EC_gen("P-256"));
    if (!key) {
        PrintOpenSslError("could not generate an ECDSA P-256 key");
    }
    return key;
}

// Adds one X.509v3 extension, e.g. ("extendedKeyUsage", "clientAuth").
bool AddExtension(X509* cert, X509* issuer, int nid, const std::string& value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value.c_str());
    if (ext == NULL) {
        PrintOpenSslError("could not build a certificate extension");
        return false;
    }
    const bool ok = X509_add_ext(cert, ext, -1) == 1;
    X509_EXTENSION_free(ext);
    return ok;
}

std::string LocalHostname() {
    char name[256] = {0};
    if (gethostname(name, sizeof(name) - 1) != 0 || name[0] == '\0') {
        return "localhost";
    }
    return name;
}

// Builds and signs one certificate. For Role::Ca the certificate is
// self-signed (issuer == NULL); otherwise `issuer` signs it.
X509Ptr MakeCertificate(Role role, const std::string& commonName, EVP_PKEY* subjectKey,
                        const Credential* issuer) {
    X509Ptr cert(X509_new());
    if (!cert) {
        return nullptr;
    }
    X509_set_version(cert.get(), 2);  // X.509 v3

    // Random positive 127-bit serial number (RFC 5280 allows up to 20 octets).
    unsigned char serialBytes[16];
    if (RAND_bytes(serialBytes, sizeof(serialBytes)) != 1) {
        PrintOpenSslError("could not generate a serial number");
        return nullptr;
    }
    serialBytes[0] &= 0x7F;
    BIGNUM* serialBn = BN_bin2bn(serialBytes, sizeof(serialBytes), NULL);
    BN_to_ASN1_INTEGER(serialBn, X509_get_serialNumber(cert.get()));
    BN_free(serialBn);

    const long days = (role == Role::Ca) ? CA_VALID_DAYS : LEAF_VALID_DAYS;
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), days * 24L * 60L * 60L);

    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_UTF8,
                               (const unsigned char*)ORGANIZATION, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                               (const unsigned char*)commonName.c_str(), -1, -1, 0);
    X509_set_issuer_name(cert.get(), issuer ? X509_get_subject_name(issuer->cert.get()) : name);
    X509_set_pubkey(cert.get(), subjectKey);

    X509* issuerCert = issuer ? issuer->cert.get() : cert.get();
    bool ok = true;
    if (role == Role::Ca) {
        ok = ok && AddExtension(cert.get(), issuerCert, NID_basic_constraints, "critical,CA:TRUE");
        ok = ok && AddExtension(cert.get(), issuerCert, NID_key_usage, "critical,keyCertSign,cRLSign");
    } else {
        ok = ok && AddExtension(cert.get(), issuerCert, NID_basic_constraints, "CA:FALSE");
        ok = ok && AddExtension(cert.get(), issuerCert, NID_key_usage, "digitalSignature,keyEncipherment");
        ok = ok && AddExtension(cert.get(), issuerCert, NID_authority_key_identifier, "keyid:always");
    }
    ok = ok && AddExtension(cert.get(), issuerCert, NID_subject_key_identifier, "hash");
    if (role == Role::Hub) {
        // The hub is a TLS server (hub function) and a TLS client (hub
        // connector), so it carries both EKUs and a SAN a peer can match.
        ok = ok && AddExtension(cert.get(), issuerCert, NID_ext_key_usage, "serverAuth,clientAuth");
        ok = ok && AddExtension(cert.get(), issuerCert, NID_subject_alt_name,
                                "DNS:localhost,IP:127.0.0.1,DNS:" + LocalHostname());
    } else if (role == Role::Client) {
        ok = ok && AddExtension(cert.get(), issuerCert, NID_ext_key_usage, "clientAuth");
    }
    if (!ok) {
        return nullptr;
    }

    EVP_PKEY* signingKey = issuer ? issuer->key.get() : subjectKey;
    if (X509_sign(cert.get(), signingKey, EVP_sha256()) == 0) {
        PrintOpenSslError("could not sign the certificate");
        return nullptr;
    }
    return cert;
}

bool WritePem(const fs::path& path, EVP_PKEY* key, X509* cert) {
    FILE* f = fopen(path.string().c_str(), "wb");
    if (f == NULL) {
        fprintf(stderr, "Error: could not create \"%s\".\n", path.string().c_str());
        return false;
    }
    const bool ok = key ? PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL) == 1
                        : PEM_write_X509(f, cert) == 1;
    fclose(f);
    if (!ok) {
        PrintOpenSslError("could not write PEM data");
        return false;
    }
    if (key) {
        // Private keys: owner read/write only (a no-op on Windows beyond the
        // read-only bit; the directory's ACL is what protects it there).
        std::error_code ec;
        fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write,
                        fs::perm_options::replace, ec);
    }
    return true;
}

// Writes a PKCS#10 certificate signing request for `key` with the same
// subject as `cert`. The hub's CSR backs Network Port 2's
// Certificate_Signing_Request_File object (File 2), which serves hub.csr.
bool WriteCsr(const fs::path& path, EVP_PKEY* key, X509* cert) {
    X509_REQ* req = X509_REQ_new();
    bool ok = req != NULL
        && X509_REQ_set_version(req, 0) == 1
        && X509_REQ_set_subject_name(req, X509_get_subject_name(cert)) == 1
        && X509_REQ_set_pubkey(req, key) == 1
        && X509_REQ_sign(req, key, EVP_sha256()) > 0;
    if (ok) {
        FILE* f = fopen(path.string().c_str(), "wb");
        ok = f != NULL && PEM_write_X509_REQ(f, req) == 1;
        if (f != NULL) {
            fclose(f);
        }
    }
    X509_REQ_free(req);
    if (!ok) {
        PrintOpenSslError("could not write the hub's certificate signing request");
    }
    return ok;
}

bool LoadCa(const fs::path& certDir, Credential* out) {
    const fs::path crtPath = certDir / "ca.crt";
    const fs::path keyPath = certDir / "ca.key";
    FILE* f = fopen(crtPath.string().c_str(), "rb");
    if (f == NULL) {
        fprintf(stderr, "Error: \"%s\" not found. Run --generate-certs first.\n", crtPath.string().c_str());
        return false;
    }
    out->cert.reset(PEM_read_X509(f, NULL, NULL, NULL));
    fclose(f);
    f = fopen(keyPath.string().c_str(), "rb");
    if (f == NULL) {
        fprintf(stderr, "Error: \"%s\" not found. The CA's private key is needed to sign new "
                        "client certificates.\n", keyPath.string().c_str());
        return false;
    }
    out->key.reset(PEM_read_PrivateKey(f, NULL, NULL, NULL));
    fclose(f);
    if (!out->cert || !out->key) {
        PrintOpenSslError("could not read the existing CA certificate/key");
        return false;
    }
    if (X509_check_private_key(out->cert.get(), out->key.get()) != 1) {
        fprintf(stderr, "Error: ca.key does not belong to ca.crt in \"%s\".\n", certDir.string().c_str());
        return false;
    }
    return true;
}

std::string SerialHex(X509* cert) {
    BIGNUM* bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), NULL);
    char* hex = BN_bn2hex(bn);
    std::string s = hex ? hex : "";
    OPENSSL_free(hex);
    BN_free(bn);
    return s;
}

std::string Sha256Fingerprint(X509* cert) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    X509_digest(cert, EVP_sha256(), md, &len);
    std::string s;
    char byte[4];
    for (unsigned int i = 0; i < len; ++i) {
        snprintf(byte, sizeof(byte), i ? ":%02X" : "%02X", md[i]);
        s += byte;
    }
    return s;
}

std::string NotAfter(X509* cert) {
    struct tm t;
    if (ASN1_TIME_to_tm(X509_get0_notAfter(cert), &t) != 1) {
        return "?";
    }
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d", &t);
    return buf;
}

// Appends one line per certificate to certificates.txt (creating it with a
// header the first time) and echoes it to stdout.
void RecordInManifest(const fs::path& certDir, const std::string& label, const std::string& role,
                      X509* cert) {
    const fs::path manifest = certDir / MANIFEST_FILE;
    const bool isNew = !fs::exists(manifest);
    FILE* f = fopen(manifest.string().c_str(), "ab");
    if (f == NULL) {
        return;
    }
    if (isNew) {
        fprintf(f, "# Lab BACnet/SC certificates generated by BACnetExampleBSCHUB (LAB TESTING ONLY).\n"
                   "# label | role | files | serial | expires | SHA-256 fingerprint\n");
    }
    fprintf(f, "%s | %s | %s.crt, %s.key | %s | %s | %s\n", label.c_str(), role.c_str(),
            label.c_str(), label.c_str(), SerialHex(cert).c_str(), NotAfter(cert).c_str(),
            Sha256Fingerprint(cert).c_str());
    fclose(f);
    printf("  %-12s %-7s %s.crt / %s.key  (expires %s)\n", label.c_str(), role.c_str(),
           label.c_str(), label.c_str(), NotAfter(cert).c_str());
}

// Generates a leaf key + certificate, signs it with `ca`, writes
// <label>.key/<label>.crt and records it. Never overwrites.
bool IssueLeaf(const fs::path& certDir, const Credential& ca, Role role, const std::string& label) {
    const fs::path crtPath = certDir / (label + ".crt");
    const fs::path keyPath = certDir / (label + ".key");
    if (fs::exists(crtPath) || fs::exists(keyPath)) {
        fprintf(stderr, "Error: \"%s\" already exists - not overwriting it.\n", crtPath.string().c_str());
        return false;
    }
    PkeyPtr key = NewP256Key();
    if (!key) {
        return false;
    }
    X509Ptr cert = MakeCertificate(role, CN_PREFIX + label, key.get(), &ca);
    if (!cert || !WritePem(keyPath, key.get(), NULL) || !WritePem(crtPath, NULL, cert.get())) {
        return false;
    }
    if (role == Role::Hub && !WriteCsr(certDir / (label + ".csr"), key.get(), cert.get())) {
        return false;
    }
    RecordInManifest(certDir, label, role == Role::Hub ? "hub" : "client", cert.get());
    return true;
}

// Highest NN among "<label>-NN.crt" files in certDir (0 if none).
unsigned HighestClientNumber(const fs::path& certDir, const std::string& label) {
    // Escape the label so a prefix like "ahu.1" is matched literally.
    const std::string escaped = std::regex_replace(label, std::regex(R"([.^$|()\[\]{}*+?\\])"), R"(\$&)");
    const std::regex pattern("^" + escaped + "-([0-9]+)\\.crt$");
    unsigned highest = 0;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(certDir, ec)) {
        std::smatch m;
        const std::string fileName = entry.path().filename().string();
        if (std::regex_match(fileName, m, pattern)) {
            const unsigned n = (unsigned)std::stoul(m[1].str());
            if (n > highest) {
                highest = n;
            }
        }
    }
    return highest;
}

std::string ClientLabel(const std::string& prefix, unsigned n) {
    char num[16];
    snprintf(num, sizeof(num), "%02u", n);
    return prefix + "-" + num;
}

bool ValidLabel(const std::string& label) {
    // File-name and CN safe: letters, digits, '-', '_', '.'.
    return !label.empty() && label != HUB_LABEL && label != "ca" &&
           std::regex_match(label, std::regex("[A-Za-z0-9_.-]+"));
}

bool IssueClients(const fs::path& certDir, const Credential& ca, unsigned count, const std::string& label) {
    const unsigned first = HighestClientNumber(certDir, label) + 1;
    for (unsigned n = first; n < first + count; ++n) {
        if (!IssueLeaf(certDir, ca, Role::Client, ClientLabel(label, n))) {
            return false;
        }
    }
    return true;
}

}  // namespace

bool GenerateCertificateSet(const std::string& certDirArg, unsigned clientCount,
                            const std::string& clientLabel, bool force) {
    if (!ValidLabel(clientLabel)) {
        fprintf(stderr, "Error: --cert-label \"%s\" must be letters, digits, '-', '_' or '.', and not "
                        "\"hub\" or \"ca\".\n", clientLabel.c_str());
        return false;
    }
    const fs::path certDir(certDirArg);
    std::error_code ec;
    fs::create_directories(certDir, ec);

    const char* const setFiles[] = {"ca.crt", "ca.key", "hub.crt", "hub.key"};
    for (const char* name : setFiles) {
        if (fs::exists(certDir / name)) {
            if (!force) {
                fprintf(stderr,
                        "Error: \"%s\" already exists. Replacing the CA invalidates every certificate "
                        "already handed out. Use --add-client-certs to add clients to the existing set, "
                        "or add --force to start over.\n",
                        (certDir / name).string().c_str());
                return false;
            }
        }
    }
    if (force) {
        // Start over: remove the old set, every client certificate and the
        // manifest, so nothing signed by the old CA is left behind.
        for (const auto& entry : fs::directory_iterator(certDir, ec)) {
            const std::string ext = entry.path().extension().string();
            const std::string fileName = entry.path().filename().string();
            if (ext == ".crt" || ext == ".key" || ext == ".csr" || ext == ".srl" || fileName == MANIFEST_FILE) {
                fs::remove(entry.path(), ec);
            }
        }
    }

    printf("Generating lab BACnet/SC certificates in \"%s\" (LAB TESTING ONLY):\n", certDir.string().c_str());
    Credential ca;
    ca.key = NewP256Key();
    if (!ca.key) {
        return false;
    }
    ca.cert = MakeCertificate(Role::Ca, CA_COMMON_NAME, ca.key.get(), NULL);
    if (!ca.cert || !WritePem(certDir / "ca.key", ca.key.get(), NULL) ||
        !WritePem(certDir / "ca.crt", NULL, ca.cert.get())) {
        return false;
    }
    RecordInManifest(certDir, "ca", "ca", ca.cert.get());

    if (!IssueLeaf(certDir, ca, Role::Hub, HUB_LABEL) || !IssueClients(certDir, ca, clientCount, clientLabel)) {
        return false;
    }
    printf("Done. Give each connecting device ca.crt plus its own <label>.crt/<label>.key.\n"
           "Keep ca.key private: it is only needed to sign more clients (--add-client-certs).\n");
    return true;
}

bool AddClientCertificates(const std::string& certDirArg, unsigned clientCount,
                           const std::string& clientLabel) {
    if (!ValidLabel(clientLabel)) {
        fprintf(stderr, "Error: --cert-label \"%s\" must be letters, digits, '-', '_' or '.', and not "
                        "\"hub\" or \"ca\".\n", clientLabel.c_str());
        return false;
    }
    const fs::path certDir(certDirArg);
    Credential ca;
    if (!LoadCa(certDir, &ca)) {
        return false;
    }
    printf("Adding %u client certificate(s) signed by the existing \"%s\":\n", clientCount,
           (certDir / "ca.crt").string().c_str());
    if (!IssueClients(certDir, ca, clientCount, clientLabel)) {
        return false;
    }
    printf("Done. The running hub already trusts these (same ca.crt) - no restart needed.\n");
    return true;
}

}  // namespace CertTool
