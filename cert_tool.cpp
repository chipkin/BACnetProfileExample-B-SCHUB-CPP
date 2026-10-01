// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// cert_tool.cpp - see cert_tool.h for what this does and why.

#include "cert_tool.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
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

// Lab certificate profile: ECDSA P-256, SHA-256.
const long CA_VALID_DAYS = 3650;
const long LEAF_VALID_DAYS = 825;
const char* const ORGANIZATION = "Chipkin Automation Systems (lab test)";
const char* const CA_COMMON_NAME = "Chipkin Example B-SCHUB Lab CA";
const char* const CN_PREFIX = "Chipkin Example B-SCHUB ";  // + label
const char* const HUB_LABEL = "hub";
const char* const ISSUER_LABEL = "issuer";

// RAII owners for the OpenSSL objects used here.
struct PkeyFree { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct X509Free { void operator()(X509* p) const { X509_free(p); } };
struct ReqFree { void operator()(X509_REQ* p) const { X509_REQ_free(p); } };
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;
using X509Ptr = std::unique_ptr<X509, X509Free>;
using ReqPtr = std::unique_ptr<X509_REQ, ReqFree>;

std::string OpenSslError() {
    const unsigned long e = ERR_get_error();
    ERR_clear_error();
    if (e == 0) {
        return std::string();
    }
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(" (") + buf + ")";
}

void PrintOpenSslError(const char* what) {
    fprintf(stderr, "Error: %s%s\n", what, OpenSslError().c_str());
}

// A certificate plus its key, as generated or loaded from disk.
struct Credential {
    PkeyPtr key;
    X509Ptr cert;
};

// Ca: self-signed issuer. Hub: this hub (serverAuth+clientAuth, SAN).
// Client: a device (clientAuth). DeviceHub: a device port that is itself a
// hub function (serverAuth+clientAuth, no SAN - BACnet/SC names devices, not
// hosts).
enum class Role { Ca, Hub, Client, DeviceHub };

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

// The hub certificate's subjectAltName: localhost, 127.0.0.1, this computer's
// host name, and the host clients will dial (from the hub URI written into
// their bacnetsc.config - this computer's LAN address by default), so a client
// that checks host names accepts wss://<that host>/ (BACnetProfileExample-B-SCHUB-CPP#9).
std::string HubSubjectAltName(const std::string& hubUri) {
    std::vector<std::string> entries = {"DNS:localhost", "IP:127.0.0.1", "DNS:" + LocalHostname()};
    // wss://host:port/path -> host (an IPv6 [literal] is left to the defaults above)
    std::string host = hubUri;
    const size_t scheme = host.find("://");
    if (scheme != std::string::npos) {
        host = host.substr(scheme + 3);
    }
    host = host.substr(0, host.find_first_of(":/"));
    if (!host.empty() && host[0] != '[') {
        const bool isIPv4 = host.find_first_not_of("0123456789.") == std::string::npos;
        entries.push_back((isIPv4 ? "IP:" : "DNS:") + host);
    }
    std::string san;
    std::set<std::string> seen;
    for (const std::string& e : entries) {
        if (seen.insert(e).second) {
            san += (san.empty() ? "" : ",") + e;
        }
    }
    return san;
}

// Builds and signs one certificate. For Role::Ca the certificate is
// self-signed (issuer == NULL); otherwise `issuer` signs it. `subject`, when
// given, is used as the certificate's subject name as it is (a device's own
// name from its CSR) instead of O=ORGANIZATION, CN=commonName.
X509Ptr MakeCertificate(Role role, const std::string& commonName, EVP_PKEY* subjectKey,
                        const Credential* issuer, const std::string& hubSubjectAltName = std::string(),
                        const X509_NAME* subject = NULL) {
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
    // Valid from an hour ago, so a device whose clock is a little behind this
    // computer's doesn't reject a freshly made certificate as "not yet valid".
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60L * 60L);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), days * 24L * 60L * 60L);

    if (subject != NULL) {
        X509_set_subject_name(cert.get(), subject);
    } else {
        X509_NAME* newName = X509_get_subject_name(cert.get());
        X509_NAME_add_entry_by_txt(newName, "O", MBSTRING_UTF8,
                                   (const unsigned char*)ORGANIZATION, -1, -1, 0);
        X509_NAME_add_entry_by_txt(newName, "CN", MBSTRING_UTF8,
                                   (const unsigned char*)commonName.c_str(), -1, -1, 0);
    }
    X509_NAME* name = X509_get_subject_name(cert.get());
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
                                hubSubjectAltName.empty() ? HubSubjectAltName(std::string()) : hubSubjectAltName);
    } else if (role == Role::DeviceHub) {
        ok = ok && AddExtension(cert.get(), issuerCert, NID_ext_key_usage, "serverAuth,clientAuth");
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

// --- PEM/DER in memory ---------------------------------------------------------

std::string BioText(BIO* bio) {
    char* data = NULL;
    const long len = BIO_get_mem_data(bio, &data);
    std::string text(data != NULL ? data : "", len > 0 ? (size_t)len : 0);
    BIO_free(bio);
    return text;
}

std::string CertPem(X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    return BioText(bio);
}

std::string KeyPem(EVP_PKEY* key) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    return BioText(bio);
}

std::string ReqPem(X509_REQ* req) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(bio, req);
    return BioText(bio);
}

std::string CertDer(X509* cert) {
    unsigned char* der = NULL;
    const int len = i2d_X509(cert, &der);
    std::string out(len > 0 ? (const char*)der : "", len > 0 ? (size_t)len : 0);
    OPENSSL_free(der);
    return out;
}

// A PKCS#12 (.pfx): `cert`, its private `key`, and `issuer` as the chain,
// under `friendlyName`, with an EMPTY password - YABE's BACnet/SC channel file
// has no password field. So the .pfx is as private as the key. 3DES and a
// SHA-1 MAC rather than OpenSSL 3's AES/SHA-256 defaults, so every Windows
// version can load it.
std::string PfxBytes(EVP_PKEY* key, X509* cert, X509* issuer, const std::string& friendlyName) {
    STACK_OF(X509)* chain = sk_X509_new_null();
    sk_X509_push(chain, issuer);
    PKCS12* p12 = PKCS12_create("", friendlyName.c_str(), key, cert, chain,
                                NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                2048, -1 /* MAC set below */, 0);
    sk_X509_free(chain);  // the issuer itself stays owned by the caller
    std::string out;
    if (p12 != NULL && PKCS12_set_mac(p12, "", -1, NULL, 0, 2048, EVP_sha1()) == 1) {
        unsigned char* der = NULL;
        const int len = i2d_PKCS12(p12, &der);
        if (len > 0) {
            out.assign((const char*)der, (size_t)len);
        }
        OPENSSL_free(der);
    }
    PKCS12_free(p12);
    return out;
}

X509Ptr CertFromPem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    X509Ptr cert(PEM_read_bio_X509(bio, NULL, NULL, NULL));
    BIO_free(bio);
    ERR_clear_error();
    return cert;
}

// Every certificate in a PEM file (a chain, or one).
std::vector<X509Ptr> CertsFromPem(const std::string& pem) {
    std::vector<X509Ptr> certs;
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    while (X509* c = PEM_read_bio_X509(bio, NULL, NULL, NULL)) {
        certs.emplace_back(c);
    }
    BIO_free(bio);
    ERR_clear_error();
    return certs;
}

// A private key, without ever prompting: an encrypted one is "unreadable".
PkeyPtr KeyFromPem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    pem_password_cb* noPassword = [](char*, int, int, void*) { return 0; };
    PkeyPtr key(PEM_read_bio_PrivateKey(bio, NULL, noPassword, NULL));
    BIO_free(bio);
    ERR_clear_error();
    return key;
}

// A certificate signing request, PEM or DER.
ReqPtr ReqFromBytes(const std::string& bytes) {
    BIO* bio = BIO_new_mem_buf(bytes.data(), (int)bytes.size());
    ReqPtr req(PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL));
    BIO_free(bio);
    if (!req) {
        ERR_clear_error();
        const unsigned char* p = (const unsigned char*)bytes.data();
        req.reset(d2i_X509_REQ(NULL, &p, (long)bytes.size()));
    }
    ERR_clear_error();
    return req;
}

ReqPtr MakeCsr(EVP_PKEY* key, const X509_NAME* subject) {
    ReqPtr req(X509_REQ_new());
    const bool ok = req && X509_REQ_set_version(req.get(), 0) == 1 &&
                    X509_REQ_set_subject_name(req.get(), subject) == 1 && X509_REQ_set_pubkey(req.get(), key) == 1 &&
                    X509_REQ_sign(req.get(), key, EVP_sha256()) > 0;
    if (!ok) {
        PrintOpenSslError("could not make the certificate signing request");
        return nullptr;
    }
    return req;
}

// O=<lab organisation>, CN=Chipkin Example B-SCHUB <label>.
struct NameFree { void operator()(X509_NAME* p) const { X509_NAME_free(p); } };
std::unique_ptr<X509_NAME, NameFree> LabSubject(const std::string& label) {
    std::unique_ptr<X509_NAME, NameFree> name(X509_NAME_new());
    const std::string cn = CN_PREFIX + label;
    X509_NAME_add_entry_by_txt(name.get(), "O", MBSTRING_UTF8, (const unsigned char*)ORGANIZATION, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_UTF8, (const unsigned char*)cn.c_str(), -1, -1, 0);
    return name;
}

std::string ReadFile(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    std::stringstream s;
    s << f.rdbuf();
    return s.str();
}

bool WriteFile(const fs::path& path, const std::string& bytes, bool isPrivate = false) {
    std::error_code ec;
    if (path.has_parent_path()) {
        fs::create_directories(path.parent_path(), ec);
    }
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        fprintf(stderr, "Error: could not create \"%s\".\n", path.string().c_str());
        return false;
    }
    f.write(bytes.data(), (std::streamsize)bytes.size());
    f.close();
    if (isPrivate) {
        // Private keys: owner read/write only (a no-op on Windows beyond the
        // read-only bit; the directory's ACL is what protects it there).
        fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
    }
    return true;
}

// --- certificate facts for the manifest and the logs -------------------------

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

// A subject name as one line of text, e.g. "CN=AHU 7,O=Example Corp".
std::string NameText(const X509_NAME* name) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return "?";
    }
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB);
    return BioText(bio);
}

std::string Today() {
    const time_t now = time(nullptr);
    struct tm t;
#if defined(_WIN32)
    gmtime_s(&t, &now);
#else
    gmtime_r(&now, &t);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", &t);
    return buf;
}

// Appends one line per certificate to certificates.txt (creating it with a
// header the first time) and echoes it to stdout. `where` is the certificate's
// location relative to certDir, e.g. "clients/client-01/".
void RecordLine(const CertLayout::HubCertPaths& paths, const std::string& label, const std::string& role,
                const std::string& where, const std::string& serial, const std::string& notAfter,
                const std::string& fingerprint) {
    const bool isNew = !fs::exists(paths.manifest);
    FILE* f = fopen(paths.manifest.c_str(), "ab");
    if (f == NULL) {
        return;
    }
    if (isNew) {
        fprintf(f, "# Lab BACnet/SC certificates generated by BACnetExampleBSCHUB (LAB TESTING ONLY).\n"
                   "# label | role | location | serial | expires | SHA-256 fingerprint\n");
    }
    const std::string location = where.empty() ? std::string("./") : where;
    fprintf(f, "%s | %s | %s | %s | %s | %s\n", label.c_str(), role.c_str(), location.c_str(), serial.c_str(),
            notAfter.c_str(), fingerprint.c_str());
    fclose(f);
    printf("  %-14s %-7s %s  (expires %s)\n", label.c_str(), role.c_str(), location.c_str(), notAfter.c_str());
}

void RecordInManifest(const CertLayout::HubCertPaths& paths, const std::string& label, const std::string& role,
                      const std::string& where, X509* cert) {
    RecordLine(paths, label, role, where, SerialHex(cert), NotAfter(cert), Sha256Fingerprint(cert));
}

// A certificate signed from a CARI zip: listed as <response zip>:<path>.
void RecordSignedItem(const CertLayout::HubCertPaths& paths, const std::string& zipName, const SignedItem& item) {
    RecordLine(paths, item.where.substr(0, item.where.find('/')), "client", zipName + ":" + item.where, item.serial,
               item.notAfter, item.fingerprint);
}

// --- the CA ------------------------------------------------------------------

// The CA that signs devices, from ca/ (or the flat/legacy names). It must be
// one of the hub's own issuers (iss-1/iss-2): a device it signs is otherwise
// refused by this very hub.
bool LoadIssuer(const CertLayout::HubCertPaths& paths, Credential* out, std::string* error) {
    if (!fs::exists(paths.caCertificate) || !fs::exists(paths.caPrivateKey)) {
        *error = "no CA to sign with: \"" + paths.caCertificate + "\" and \"" + paths.caPrivateKey +
                 "\" are needed (run --generate-certs first, or copy your CA's certificate and key there)";
        return false;
    }
    out->cert = CertFromPem(ReadFile(paths.caCertificate));
    out->key = KeyFromPem(ReadFile(paths.caPrivateKey));
    if (!out->cert) {
        *error = "\"" + paths.caCertificate + "\" is not a PEM certificate";
        return false;
    }
    if (!out->key) {
        *error = "\"" + paths.caPrivateKey + "\" is not an unencrypted PEM private key";
        return false;
    }
    if (X509_check_private_key(out->cert.get(), out->key.get()) != 1) {
        ERR_clear_error();
        *error = "\"" + paths.caPrivateKey + "\" is not the key of \"" + paths.caCertificate + "\"";
        return false;
    }
    const std::string caDer = CertDer(out->cert.get());
    for (const std::string& issuerPath : {paths.issuerCertificate1, paths.issuerCertificate2}) {
        for (const X509Ptr& c : CertsFromPem(ReadFile(issuerPath))) {
            if (CertDer(c.get()) == caDer) {
                return true;
            }
        }
    }
    *error = "the CA \"" + paths.caCertificate + "\" is not one of the hub's issuer certificates (" +
             paths.issuerCertificate1 + ", " + paths.issuerCertificate2 +
             "), so the hub would refuse every device it signs. Put the CA certificate in an issuer slot first.";
    return false;
}

// The checks a CA makes before signing: the request is signed by the key it
// carries (so the requester holds that private key), that key is strong
// enough, and there is a subject to put in the certificate.
bool CheckCsr(X509_REQ* req, std::string* reason) {
    EVP_PKEY* key = X509_REQ_get0_pubkey(req);
    if (key == NULL || X509_REQ_verify(req, key) != 1) {
        *reason = "the request's signature does not verify - it is damaged, or was not made with the key it "
                  "contains" + OpenSslError();
        return false;
    }
    const int type = EVP_PKEY_get_base_id(key);
    const int bits = EVP_PKEY_get_bits(key);
    if (!((type == EVP_PKEY_EC && bits >= 256) || (type == EVP_PKEY_RSA && bits >= 2048))) {
        *reason = std::string("the request's key is ") + EVP_PKEY_get0_type_name(key) + " " + std::to_string(bits) +
                  "-bit; BACnet/SC needs ECDSA P-256 or stronger, or RSA 2048-bit or stronger";
        return false;
    }
    if (X509_NAME_entry_count(X509_REQ_get_subject_name(req)) == 0) {
        *reason = "the request has an empty subject - there is nothing to name the device by";
        return false;
    }
    return true;
}

// --- text files ---------------------------------------------------------------

std::string ReplaceAll(std::string text, const std::string& from, const std::string& to) {
    for (size_t pos = text.find(from); pos != std::string::npos; pos = text.find(from, pos + to.size())) {
        text.replace(pos, from.size(), to);
    }
    return text;
}

std::string XmlEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default: out += c; break;
        }
    }
    return out;
}

// bacnetsc.config for one device folder: the BACnet/SC connection settings in
// the XML format the CAS BACnet Explorer imports. Role "device" = a node that
// connects to a hub; ValidateHubCertificate makes it check the hub's
// certificate against the issuer file. Paths are relative to the folder.
std::string BacnetScConfig(const std::string& hubUri, const std::string& opr, const std::string& key,
                           const std::string& issuer) {
    std::string xml;
    xml += "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    xml += "<BACnetSCConfigChannel>\n";
    xml += "    <Role>device</Role>\n";
    xml += "    <primaryHubURI>" + XmlEscape(hubUri) + "</primaryHubURI>\n";
    xml += "    <failoverHubURI></failoverHubURI>\n";
    xml += "    <operationalCertificate>" + XmlEscape(opr) + "</operationalCertificate>\n";
    xml += "    <devicePrivateKeyFile>" + XmlEscape(key) + "</devicePrivateKeyFile>\n";
    xml += "    <issuerCertificate>" + XmlEscape(issuer) + "</issuerCertificate>\n";
    xml += "    <ValidateHubCertificate>true</ValidateHubCertificate>\n";
    xml += "</BACnetSCConfigChannel>\n";
    return xml;
}

// yabe-bacnetsc.config: YABE's BACnet/SC channel file (the format of
// BACnetSCConfig.config next to Yabe.exe). YABE resolves relative names
// against its own folder, so the files are given by absolute path.
std::string YabeConfig(const std::string& hubUri, const fs::path& pfxPath, const fs::path& issuerPath) {
    std::string uri = hubUri;  // YABE's own example writes the URI without a trailing '/'
    while (!uri.empty() && uri.back() == '/') {
        uri.pop_back();
    }
    std::error_code ec;
    const std::string pfx = fs::absolute(pfxPath, ec).make_preferred().string();
    const std::string ca = fs::absolute(issuerPath, ec).make_preferred().string();
    std::string xml;
    xml += "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    xml += "<BACnetSCConfigChannel>\n";
    xml += "  <primaryHubURI>" + XmlEscape(uri) + "</primaryHubURI>\n";
    xml += "  <failoverHubURI>" + XmlEscape(uri) + "</failoverHubURI>\n";
    xml += "  <OwnCertificateFile>" + XmlEscape(pfx) + "</OwnCertificateFile>\n";
    xml += "  <HubCertificateFile>" + XmlEscape(ca) + "</HubCertificateFile>\n";
    xml += "  <ValidateHubCertificate>true</ValidateHubCertificate>\n";
    xml += "</BACnetSCConfigChannel>\n";
    return xml;
}

// readme.txt for the certificate folder: what each file is, whether it is
// private, what the BACnet standard says it is for, and how to use the set.
// Rewritten on every run so it never goes stale.
const char* const CERT_DIR_README = R"(BACnet/SC lab certificates - generated by BACnetExampleBSCHUB
==============================================================

LAB TESTING ONLY. These certificates come from a throwaway certificate
authority made on this computer. Use your own PKI (or a real CA) for a
production installation.

BACnet/SC (ANSI/ASHRAE 135-2024 Annex AB) runs BACnet over secure WebSockets:
every connection is TLS 1.3 with mutual authentication, so BOTH ends present
a certificate, and each end accepts the other only if that certificate was
signed by an issuer it trusts.

The files are laid out in the CARI format (Certificate Authority
Requirements Interchange, ANSI/ASHRAE 135-2024 Annex AA.2, added by
Addendum cs to 135-2020), the folder-and-file layout BACnet uses to carry
certificate signing requests to a CA and certificates back. The names
follow the Network Port properties that carry them (clause 12.56).


THE HUB'S OWN FILES
-------------------

cert1/                                                    the hub's CARI tree
  device-<instance>/port-2/                               Network Port 2 "BACnet SC"
    hub/                                                  empty: this port is a hub function
    opr-hub.pem                                  PUBLIC   File 1, Operational_Certificate_File:
                                                          the certificate the hub presents.
                                                          TLS server and client; its Subject
                                                          Alternative Name lists localhost,
                                                          127.0.0.1 and this computer's names.
    key-hub.pem                                  PRIVATE  Its private key. Only TLS reads it;
                                                          no File object serves it. Anyone with
                                                          it can impersonate the hub.
    csr-hub.pem                                  PUBLIC   File 2, Certificate_Signing_Request_File:
                                                          a request for the hub's key. Give it
                                                          (or the whole cert1/ folder, zipped) to
                                                          your site CA to move onto your own PKI.
  issuer/
    iss-1.pem                                    PUBLIC   File 3, Issuer_Certificate_Files[1]: the
                                                          CA that signed the hub and every device.
                                                          Every device needs a copy.
    iss-2.pem                                    PUBLIC   File 4, Issuer_Certificate_Files[2]. Only
                                                          once a second issuer is added (over
                                                          BACnet or POST /certs/issuer2); until
                                                          then File 4 serves iss-1.pem.

ca/ca-cert.pem                                   PUBLIC   The lab CA's certificate (= iss-1.pem).
ca/ca-key.pem                                    PRIVATE  The lab CA's key. It is the only thing
                                                          that can sign certificates this hub
                                                          trusts. Used only by --add-client-certs,
                                                          --sign-csr and the web set-up guide; the
                                                          hub's TLS never reads it. Keep it off the
                                                          network in production.

key-hub-pending.pem                              PRIVATE  Only after a GENERATE_CSR_FILE: the new
                                                          key behind csr-hub.pem. It replaces
                                                          key-hub.pem when a certificate for it is
                                                          activated.
trusted-issuers.pem                              PUBLIC   Written by the hub: every issuer from both
                                                          slots - what TLS trusts. Don't edit it.
issuer-crl.pem                                   PUBLIC   Optional, from your CA: revoked
                                                          certificates. Never written by the hub.
certificates.txt                                 PUBLIC   One line per certificate: label,
                                                          location, serial, expiry, fingerprint.


ONE FOLDER PER DEVICE: clients/<label>/
---------------------------------------

cert1/device-<n>/port-<id>/opr-<label>.pem       PUBLIC   The device's operational certificate.
cert1/device-<n>/port-<id>/key-<label>.pem       PRIVATE  Its private key (only when the hub made
                                                          it; a device that sent its own CSR keeps
                                                          its key).
cert1/device-<n>/port-<id>/csr-<label>.pem       PUBLIC   The request it was signed from.
cert1/issuer/iss-1.pem                           PUBLIC   The issuer, to validate the hub.
<label>-cari-response.zip                                 The cert1/ tree above as a CARI file.
bacnetsc.config                                  PUBLIC   Import into the CAS BACnet Explorer.
<label>.pfx                                      PRIVATE  Certificate + key + issuer for Windows
                                                          tools (YABE). EMPTY password.
iss-1.cer, yabe-bacnetsc.config                  PUBLIC   For YABE (Windows 11 or later).
readme.txt                                       PUBLIC   A note for whoever gets the folder.


HOW TO USE THESE FILES
----------------------

1. Start the hub with this folder:   BACnetExampleBSCHUB --sc-cert-dir <this folder>
   It listens on wss://<this computer>:4443/ (change with --sc-port).

2. Easiest: open http://127.0.0.1:8080/setup on the hub's computer - the
   set-up guide signs a device's CSR or makes its files, and shows every
   field of every file.

3. Or give each device its own clients/<label>/ folder, and install on it:
     opr-<label>.pem  -> its Operational_Certificate_File
     key-<label>.pem  -> its private key
     iss-1.pem        -> its Issuer_Certificate_Files (both slots, if two)
     primary hub URI  -> the primaryHubURI in bacnetsc.config

4. More devices, signed by the SAME CA (the running hub trusts them at once):
       BACnetExampleBSCHUB --sc-cert-dir <this folder> --add-client-certs 2
   A device that makes its own key: sign its CSR or CARI request file -
       BACnetExampleBSCHUB --sc-cert-dir <this folder> --sign-csr request.zip
   gives request-response.zip, with opr-*.pem next to each CSR and
   cert1/issuer/iss-1.pem, and errors.txt for anything refused.

5. Check a certificate (any OpenSSL):
       openssl verify -CAfile cert1/issuer/iss-1.pem clients/<label>/cert1/device-1/port-1/opr-<label>.pem

6. Starting over: "--generate-certs --force" deletes this whole set,
   including clients/, and makes a new CA. Every device then needs new files.


KEY AND CERTIFICATE DETAILS
---------------------------

    Keys:          ECDSA P-256 (prime256v1), PEM (PKCS#8)
    Signatures:    SHA-256
    CA:            valid 10 years; CA:TRUE; keyCertSign, cRLSign
    Hub:           valid 825 days; EKU serverAuth + clientAuth
    Devices:       valid 825 days; EKU clientAuth (+ serverAuth on a hub port)
)";

// Short note in each clients/<label>/ folder, for whoever receives it.
const char* const CLIENT_DIR_README = R"(BACnet/SC device certificate "%LABEL%" - LAB TESTING ONLY
Made by BACnetExampleBSCHUB for ONE device that connects to its BACnet/SC hub.

The cert1/ folder is a CARI response (ANSI/ASHRAE 135-2024 Annex AA.2); <label>-cari-response.zip is the
same thing zipped, for tools that import CARI files.

%OPR%
        PUBLIC   This device's operational certificate -> its Operational_Certificate_File.
                 Subject: %SUBJECT%
%KEY%
        %KEYNOTE%
cert1/issuer/iss-1.pem
        PUBLIC   The CA that signed the hub's certificate -> the device's Issuer_Certificate_Files
                 (load it into both slots if there are two).
bacnetsc.config  PUBLIC   Settings for the CAS BACnet Explorer: hub URI %HUBURI% and the files above.
%PFXNOTE%
To connect any other BACnet/SC device: install the operational certificate and key, install
iss-1.pem as its issuer certificate, and set its primary hub URI to %HUBURI%.
)";

const char* const CSR_DIR_README = R"(BACnet/SC certificate request "%LABEL%"
Made by BACnetExampleBSCHUB --generate-csr for ONE device that will connect to a BACnet/SC hub.

%CSR%
        PUBLIC   The request (PKCS#10) for this device's key. Subject: "%SUBJECT%".
%KEY%
        PRIVATE  This device's private key. Keep it on this device only.
%LABEL%-cari-request.zip
        PUBLIC   The cert1/ folder as a CARI request file (ANSI/ASHRAE 135-2024 Annex AA.2), the format
                 a BACnet/SC certificate authority takes. Send it (or the CSR) to whoever runs the hub.

The hub signs it with either of
    BACnetExampleBSCHUB --sc-cert-dir <hub folder> --sign-csr %LABEL%-cari-request.zip
    the set-up guide at http://<hub>:8080/setup
and returns a CARI response: the same tree plus opr-%LABEL%.pem (the certificate) and
cert1/issuer/iss-1.pem.
)";

// --- labels -----------------------------------------------------------------

// Highest NN among clients/<prefix>-NN folders (0 if none).
unsigned HighestClientNumber(const fs::path& clientsDir, const std::string& prefix) {
    const std::string escaped = std::regex_replace(prefix, std::regex(R"([.^$|()\[\]{}*+?\\])"), R"(\$&)");
    const std::regex pattern("^" + escaped + "-([0-9]+)$");
    unsigned highest = 0;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(clientsDir, ec)) {
        std::smatch m;
        const std::string name = entry.path().filename().string();
        if (entry.is_directory() && std::regex_match(name, m, pattern)) {
            // strtoul, not stoul: a folder like "client-99999999999999999999"
            // must not throw. Out-of-range numbers are ignored.
            errno = 0;
            const unsigned long parsed = std::strtoul(m[1].str().c_str(), nullptr, 10);
            if (errno == ERANGE || parsed > 99999) {
                continue;
            }
            if ((unsigned)parsed > highest) {
                highest = (unsigned)parsed;
            }
        }
    }
    return highest;
}

std::string NumberedLabel(const std::string& prefix, unsigned n) {
    char num[16];
    snprintf(num, sizeof(num), "%02u", n);
    return prefix + "-" + num;
}

// The number at the end of client-NN (0 if none) - the default device instance.
unsigned LabelNumber(const std::string& label) {
    const size_t dash = label.rfind('-');
    if (dash == std::string::npos || dash + 1 >= label.size() ||
        label.find_first_not_of("0123456789", dash + 1) != std::string::npos) {
        return 0;
    }
    return (unsigned)std::strtoul(label.c_str() + dash + 1, nullptr, 10);
}

bool CheckLabel(const std::string& label) {
    if (!IsValidLabel(label)) {
        fprintf(stderr, "Error: --cert-label \"%s\" must be letters, digits, '-', '_' or '.', and not "
                        "\"%s\" or \"%s\".\n", label.c_str(), HUB_LABEL, ISSUER_LABEL);
        return false;
    }
    return true;
}

uint32_t DeviceInstanceFor(const ClientOptions& client, const std::string& label, unsigned offset) {
    if (client.deviceInstance >= 0) {
        return (uint32_t)client.deviceInstance + offset;
    }
    const unsigned n = LabelNumber(label);
    return n != 0 ? n : 1;
}

std::string PortFolder(const ClientOptions& client, uint32_t instance) {
    return "cert1/device-" + std::to_string(instance) + "/port-" + client.portId;
}

// The hub's issuer files, as they go into a response's cert1/issuer/.
void AddIssuers(const CertLayout::HubCertPaths& paths, Cari::Tree* tree) {
    tree->AddFile("cert1/issuer/iss-1.pem", ReadFile(paths.issuerCertificate1));
    if (fs::exists(paths.issuerCertificate2)) {
        const std::string second = ReadFile(paths.issuerCertificate2);
        if (!second.empty() && second != tree->files["cert1/issuer/iss-1.pem"]) {
            tree->AddFile("cert1/issuer/iss-2.pem", second);
        }
    }
}

// The hub URI written into bacnetsc.config when none was given.
std::string DefaultHubUri(const ClientOptions& client) {
    return client.hubUri.empty() ? std::string("wss://127.0.0.1:4443/") : client.hubUri;
}

// The hub's own files: key, certificate, CSR and the hub/ marker.
bool IssueHub(const CertLayout::HubCertPaths& paths, const Credential& issuer, const std::string& hubUri) {
    PkeyPtr key = NewP256Key();
    if (!key) {
        return false;
    }
    X509Ptr cert = MakeCertificate(Role::Hub, CN_PREFIX + std::string(HUB_LABEL), key.get(), &issuer,
                                   HubSubjectAltName(hubUri));
    if (!cert) {
        return false;
    }
    ReqPtr csr = MakeCsr(key.get(), X509_get_subject_name(cert.get()));
    std::error_code ec;
    fs::create_directories(fs::path(paths.certDir) / paths.portFolder / "hub", ec);
    if (!csr || !WriteFile(paths.privateKey, KeyPem(key.get()), true) ||
        !WriteFile(paths.operationalCertificate, CertPem(cert.get())) ||
        !WriteFile(paths.certificateSigningRequest, ReqPem(csr.get()))) {
        return false;
    }
    RecordInManifest(paths, HUB_LABEL, "hub", paths.portFolder + "/", cert.get());
    return true;
}

}  // namespace

// =============================================================================
// Building blocks
// =============================================================================

bool CheckSigningCa(const CertLayout::HubCertPaths& paths, std::string* error) {
    Credential issuer;
    return LoadIssuer(paths, &issuer, error);
}

bool IsValidLabel(const std::string& label) {
    return !label.empty() && label.size() <= 64 && label != HUB_LABEL && label != ISSUER_LABEL &&
           std::regex_match(label, std::regex("[A-Za-z0-9_.-]+"));
}

std::string NextClientLabel(const std::string& certDir, const ClientOptions& client) {
    if (!client.label.empty()) {
        return client.label;
    }
    const fs::path clients = fs::path(certDir) / CLIENTS_DIR;
    return NumberedLabel(client.labelPrefix, HighestClientNumber(clients, client.labelPrefix) + 1);
}

bool BareCsrToRequest(const std::string& csrBytes, const ClientOptions& client, const std::string& label,
                      Cari::Tree* request, std::string* error) {
    ReqPtr req = ReqFromBytes(csrBytes);
    if (!req) {
        *error = "the file is not a certificate signing request (PKCS#10, PEM or DER)";
        return false;
    }
    if (!Cari::IsValidName(client.portId)) {
        *error = "port id \"" + client.portId + "\" may not contain < > : \" / \\ | ? *";
        return false;
    }
    *request = Cari::Tree();
    request->AddFile(PortFolder(client, DeviceInstanceFor(client, label, 0)) + "/csr-" + label + ".pem",
                     ReqPem(req.get()));
    return true;
}

bool SignCariTree(const CertLayout::HubCertPaths& paths, const Cari::Tree& request, Cari::Tree* response,
                  std::vector<SignedItem>* items, std::string* error) {
    items->clear();
    // A request may already hold response-only files (a re-submitted
    // response): they are replaced, so accept the response names here.
    std::vector<std::string> problems;
    if (!Cari::Validate(request, true, &problems)) {
        *error = "not a valid CARI request:\n  " + problems[0];
        for (size_t i = 1; i < problems.size() && i < 20; ++i) {
            *error += "\n  " + problems[i];
        }
        return false;
    }
    const std::vector<Cari::CsrEntry> csrs = Cari::ListCsrs(request);
    if (csrs.empty()) {
        *error = "the CARI request has no csr-<name>.pem file in any port folder";
        return false;
    }
    Credential issuer;
    if (!LoadIssuer(paths, &issuer, error)) {
        return false;
    }

    // The response keeps every request file except those the CA writes.
    *response = request;
    for (auto it = response->files.begin(); it != response->files.end();) {
        const std::string name = fs::path(it->first).filename().string();
        const bool caFile = it->first.compare(0, 13, "cert1/issuer/") == 0 || it->first == "cert1/errors.txt" ||
                            it->first == "cert1/response-notes.txt" || name.compare(0, 4, "opr-") == 0;
        it = caFile ? response->files.erase(it) : std::next(it);
    }

    std::string errors;
    unsigned signedCount = 0;
    for (const Cari::CsrEntry& csr : csrs) {
        SignedItem item;
        item.where = csr.deviceFolder + "/" + csr.portFolder + "/csr-" + csr.name + ".pem";
        item.isHubPort = csr.isHubPort;
        ReqPtr req = ReqFromBytes(request.files.at(csr.csrPath));
        std::string reason;
        if (!req) {
            reason = "not a PKCS#10 certificate signing request";
        } else if (CheckCsr(req.get(), &reason)) {
            if (!csr.keyPath.empty()) {
                // key-<name>.pem is optional and ignored by a CA - but a key
                // that isn't the CSR's means the files were mixed up.
                PkeyPtr key = KeyFromPem(request.files.at(csr.keyPath));
                if (key && EVP_PKEY_eq(key.get(), X509_REQ_get0_pubkey(req.get())) != 1) {
                    reason = "key-" + csr.name + ".pem is not the key this CSR is for";
                }
            }
        }
        if (reason.empty()) {
            X509Ptr cert = MakeCertificate(csr.isHubPort ? Role::DeviceHub : Role::Client, std::string(),
                                           X509_REQ_get0_pubkey(req.get()), &issuer, std::string(),
                                           X509_REQ_get_subject_name(req.get()));
            if (!cert) {
                reason = "signing failed" + OpenSslError();
            } else {
                response->AddFile(csr.oprPath, CertPem(cert.get()));
                item.signedOk = true;
                item.subject = NameText(X509_get_subject_name(cert.get()));
                item.serial = SerialHex(cert.get());
                item.notAfter = NotAfter(cert.get());
                item.fingerprint = Sha256Fingerprint(cert.get());
                ++signedCount;
            }
        }
        if (!item.signedOk) {
            item.error = reason;
            // AA.2.1.2: one tab-separated line per error.
            errors += csr.deviceFolder + "\t" + csr.portFolder + "\t" + "csr-" + csr.name + ".pem: " + reason + "\n";
        }
        items->push_back(item);
    }
    AddIssuers(paths, response);
    if (!errors.empty()) {
        response->AddFile("cert1/errors.txt", errors);
    }
    response->AddFile("cert1/response-notes.txt",
                      "Processed by the BACnetExampleBSCHUB lab CA (" + NameText(X509_get_subject_name(issuer.cert.get())) +
                      ") on " + Today() + ": " + std::to_string(signedCount) + " signed, " +
                      std::to_string(csrs.size() - signedCount) + " refused" +
                      (errors.empty() ? "." : " - see errors.txt.") + "\n");
    return true;
}

bool WriteClientFolder(const CertLayout::HubCertPaths& paths, const std::string& label, const Cari::Tree& response,
                       const std::string& hubUri, std::string* folder, std::string* error) {
    const fs::path dir = fs::path(paths.clientsDir) / label;
    *folder = dir.generic_string();
    const std::vector<Cari::CsrEntry> csrs = Cari::ListCsrs(response);
    const Cari::CsrEntry* csr = nullptr;
    for (const Cari::CsrEntry& c : csrs) {
        if (response.Has(c.oprPath)) {
            csr = &c;
            break;
        }
    }
    if (csr == nullptr) {
        *error = "no signed certificate to put in the device folder";
        return false;
    }
    std::error_code ec;
    fs::remove_all(dir / "cert1", ec);  // the tree is replaced as a whole
    if (!Cari::WriteToDir(response, dir.string(), error) ||
        !WriteFile(dir / (label + "-cari-response.zip"), Cari::WriteZip(response))) {
        return false;
    }
    X509Ptr cert = CertFromPem(response.files.at(csr->oprPath));
    X509Ptr issuer = CertFromPem(response.files.at("cert1/issuer/iss-1.pem"));
    const std::string keyRel = csr->keyPath.empty() ? csr->oprPath.substr(0, csr->oprPath.rfind('/')) + "/key-" +
                                                          csr->name + ".pem"
                                                    : csr->keyPath;
    PkeyPtr key = csr->keyPath.empty() ? nullptr : KeyFromPem(response.files.at(csr->keyPath));
    if (!cert || !issuer || !WriteFile(dir / ISSUER_CERTIFICATE_DER_FILE, CertDer(issuer.get())) ||
        !WriteFile(dir / BACNETSC_CONFIG_FILE, BacnetScConfig(hubUri, csr->oprPath, keyRel, "cert1/issuer/iss-1.pem"))) {
        *error = "could not write the device folder's tool files";
        return false;
    }
    std::string pfxNote;
    if (key && EVP_PKEY_eq(key.get(), X509_get0_pubkey(cert.get())) == 1) {
        const fs::path pfxPath = dir / (label + CLIENT_PFX_EXTENSION);
        if (!WriteFile(pfxPath, PfxBytes(key.get(), cert.get(), issuer.get(), CN_PREFIX + label), true) ||
            !WriteFile(dir / YABE_CONFIG_FILE, YabeConfig(hubUri, pfxPath, dir / ISSUER_CERTIFICATE_DER_FILE))) {
            *error = "could not write the .pfx / YABE files";
            return false;
        }
        pfxNote = label + ".pfx       PRIVATE  Certificate + key + issuer in one PKCS#12 file for Windows tools (YABE).\n"
                  "                 EMPTY password - as private as the key.\n"
                  "iss-1.cer, yabe-bacnetsc.config\n"
                  "                 For YABE: Communication Channel -> BACnet/Secure Connect -> Select\n"
                  "                 yabe-bacnetsc.config -> Start. Needs Windows 11 or later (TLS 1.3).\n";
    } else {
        pfxNote = "iss-1.cer        PUBLIC   iss-1.pem in DER form, for Windows tools.\n";
    }
    std::string text = ReplaceAll(CLIENT_DIR_README, "%LABEL%", label);
    text = ReplaceAll(text, "<label>", label);
    text = ReplaceAll(text, "%OPR%", csr->oprPath);
    text = ReplaceAll(text, "%KEY%", keyRel);
    text = ReplaceAll(text, "%KEYNOTE%", key ? "PRIVATE  This device's private key. Keep it on this device only."
                                             : "(not here) The device made this key itself and kept it - "
                                               "install the certificate with that key.");
    text = ReplaceAll(text, "%SUBJECT%", NameText(X509_get_subject_name(cert.get())));
    text = ReplaceAll(text, "%HUBURI%", hubUri);
    text = ReplaceAll(text, "%PFXNOTE%", pfxNote);
    if (!WriteFile(dir / "readme.txt", text)) {
        *error = "could not write readme.txt";
        return false;
    }
    RecordInManifest(paths, label, "client", std::string(CLIENTS_DIR) + "/" + label + "/", cert.get());
    return true;
}

bool IssueClientFolder(const CertLayout::HubCertPaths& paths, const ClientOptions& client, std::string* folder,
                       std::vector<SignedItem>* items, std::string* error) {
    const std::string label = NextClientLabel(paths.certDir, client);
    if (!IsValidLabel(label)) {
        *error = "the label \"" + label + "\" must be letters, digits, '-', '_' or '.'";
        return false;
    }
    if (!Cari::IsValidName(client.portId)) {
        *error = "port id \"" + client.portId + "\" may not contain < > : \" / \\ | ? *";
        return false;
    }
    if (fs::exists(fs::path(paths.clientsDir) / label)) {
        *error = "clients/" + label + " already exists - choose another label";
        return false;
    }
    PkeyPtr key = NewP256Key();
    if (!key) {
        *error = "could not generate a key";
        return false;
    }
    ReqPtr csr = MakeCsr(key.get(), LabSubject(label).get());
    if (!csr) {
        *error = "could not make the CSR";
        return false;
    }
    const std::string port = PortFolder(client, DeviceInstanceFor(client, label, 0));
    Cari::Tree request;
    request.AddFile(port + "/csr-" + label + ".pem", ReqPem(csr.get()));
    request.AddFile(port + "/key-" + label + ".pem", KeyPem(key.get()));
    Cari::Tree response;
    if (!SignCariTree(paths, request, &response, items, error)) {
        return false;
    }
    if (items->empty() || !(*items)[0].signedOk) {
        *error = items->empty() ? "nothing signed" : (*items)[0].error;
        return false;
    }
    return WriteClientFolder(paths, label, response, DefaultHubUri(client), folder, error);
}

// =============================================================================
// Command-line modes
// =============================================================================

namespace {

void PrintItems(const std::vector<SignedItem>& items) {
    for (const SignedItem& item : items) {
        if (item.signedOk) {
            printf("  signed   %s\n           %s, serial %s, expires %s%s\n", item.where.c_str(), item.subject.c_str(),
                   item.serial.c_str(), item.notAfter.c_str(), item.isHubPort ? " (hub port: serverAuth too)" : "");
        } else {
            printf("  REFUSED  %s\n           %s\n", item.where.c_str(), item.error.c_str());
        }
    }
}

bool IssueClients(const CertLayout::HubCertPaths& paths, unsigned count, const ClientOptions& clients) {
    const unsigned first = HighestClientNumber(paths.clientsDir, clients.labelPrefix) + 1;
    for (unsigned i = 0; i < count; ++i) {
        ClientOptions one = clients;
        one.label = NumberedLabel(clients.labelPrefix, first + i);
        if (clients.deviceInstance >= 0) {
            one.deviceInstance = clients.deviceInstance + i;
        }
        std::string folder;
        std::string error;
        std::vector<SignedItem> items;
        if (!IssueClientFolder(paths, one, &folder, &items, &error)) {
            fprintf(stderr, "Error: %s\n", error.c_str());
            return false;
        }
    }
    return true;
}

// Every file name a certificate set may own, in all three layouts.
const char* const kSetFiles[] = {
    "operational-certificate.pem", "private-key.pem", "certificate-signing-request.pem", "issuer-certificate.pem",
    "issuer-certificate-2.pem", "issuer-private-key.pem", "private-key-pending.pem",
    "hub.crt", "hub.key", "hub.csr", "ca.crt", "ca.key", "ca.srl", "node.crt", "node.key",
    "key-hub-pending.pem", "trusted-issuers.pem",
    // The CRL is the OLD CA's: left behind, it makes the hub refuse every
    // certificate from a new CA ("unable to get certificate CRL").
    "issuer-crl.pem", "certificates.txt", "readme.txt"};

}  // namespace

bool GenerateCertificateSet(const std::string& certDirArg, uint32_t hubDeviceInstance, unsigned clientCount,
                            const ClientOptions& clients, bool force) {
    if (!CheckLabel(clients.labelPrefix)) {
        return false;
    }
    const fs::path certDir(certDirArg);
    std::error_code ec;
    fs::create_directories(certDir, ec);

    const char* const ownedFolders[] = {"cert1", "ca"};
    if (!force) {
        for (const char* name : kSetFiles) {
            const std::string n = name;
            if (fs::exists(certDir / name) && n != "certificates.txt" && n != "readme.txt" && n != "trusted-issuers.pem") {
                fprintf(stderr, "Error: \"%s\" already exists. Replacing the CA invalidates every certificate "
                                "already handed out. Use --add-client-certs to add devices to the existing set, "
                                "or add --force to start over.\n", (certDir / name).string().c_str());
                return false;
            }
        }
        for (const char* folder : ownedFolders) {
            if (fs::exists(certDir / folder)) {
                fprintf(stderr, "Error: \"%s\" already exists - this folder already has a certificate set. Use "
                                "--add-client-certs to add devices, or add --force to start over.\n",
                        (certDir / folder).string().c_str());
                return false;
            }
        }
    } else {
        // Start over: remove the old set, every device folder and the
        // manifest, so nothing signed by the old CA is left behind.
        for (const char* name : kSetFiles) {
            fs::remove(certDir / name, ec);
        }
        for (const char* folder : ownedFolders) {
            fs::remove_all(certDir / folder, ec);
        }
        fs::remove_all(certDir / CLIENTS_DIR, ec);
    }

    const CertLayout::HubCertPaths paths = CertLayout::CariHubCertPaths(certDirArg, hubDeviceInstance);
    printf("Generating lab BACnet/SC certificates in \"%s\" (CARI layout, LAB TESTING ONLY):\n",
           certDir.string().c_str());
    Credential issuer;
    issuer.key = NewP256Key();
    if (!issuer.key) {
        return false;
    }
    // A short random suffix gives every lab CA its own subject name, so two
    // certificate sets (e.g. an "add issuer" test) never have issuers that can
    // only be told apart by key identifier.
    unsigned char suffix[4];
    RAND_bytes(suffix, sizeof(suffix));
    char suffixHex[9];
    snprintf(suffixHex, sizeof(suffixHex), "%02X%02X%02X%02X", suffix[0], suffix[1], suffix[2], suffix[3]);
    issuer.cert = MakeCertificate(Role::Ca, std::string(CA_COMMON_NAME) + " " + suffixHex, issuer.key.get(), NULL);
    if (!issuer.cert || !WriteFile(paths.caPrivateKey, KeyPem(issuer.key.get()), true) ||
        !WriteFile(paths.caCertificate, CertPem(issuer.cert.get())) ||
        !WriteFile(paths.issuerCertificate1, CertPem(issuer.cert.get()))) {
        return false;
    }
    RecordInManifest(paths, ISSUER_LABEL, "issuer", "cert1/issuer/iss-1.pem", issuer.cert.get());

    const std::string hubUri = DefaultHubUri(clients);
    if (!IssueHub(paths, issuer, hubUri) || !IssueClients(paths, clientCount, clients) ||
        !WriteFile(paths.readme, CERT_DIR_README)) {
        return false;
    }
    printf("Wrote readme.txt: what each file is, which are private, and how to use them.\n");
    printf("Device bacnetsc.config files point at %s (change with --cert-hub-uri).\n", hubUri.c_str());
    printf("Done. Give each connecting device its own %s/<label>/ folder, or use the set-up guide at\n"
           "http://127.0.0.1:8080/setup while the hub runs.\n"
           "Keep ca/ca-key.pem private: it is only needed to sign more devices.\n", CLIENTS_DIR);
    return true;
}

bool AddClientCertificates(const std::string& certDirArg, uint32_t hubDeviceInstance, unsigned clientCount,
                           const ClientOptions& clients) {
    if (!CheckLabel(clients.labelPrefix)) {
        return false;
    }
    const CertLayout::HubCertPaths paths = CertLayout::ResolveHubCertPaths(certDirArg, hubDeviceInstance);
    printf("Adding %u device certificate(s) signed by the existing CA in \"%s\":\n", clientCount, certDirArg.c_str());
    if (!IssueClients(paths, clientCount, clients) || !WriteFile(paths.readme, CERT_DIR_README)) {
        return false;
    }
    printf("Done. The running hub already trusts these (same CA) - no restart needed.\n");
    return true;
}

bool GenerateClientCsr(const std::string& certDirArg, const ClientOptions& client) {
    const std::string label = NextClientLabel(certDirArg, client);
    if (!CheckLabel(label)) {
        return false;
    }
    if (!Cari::IsValidName(client.portId)) {
        fprintf(stderr, "Error: --cert-port-id \"%s\" may not contain < > : \" / \\ | ? *\n", client.portId.c_str());
        return false;
    }
    const fs::path dir = fs::path(certDirArg) / CLIENTS_DIR / label;
    if (fs::exists(dir / "cert1")) {
        fprintf(stderr, "Error: \"%s\" already exists - not overwriting it.\n", (dir / "cert1").string().c_str());
        return false;
    }
    PkeyPtr key = NewP256Key();
    if (!key) {
        return false;
    }
    ReqPtr csr = MakeCsr(key.get(), LabSubject(label).get());
    if (!csr) {
        return false;
    }
    const std::string port = PortFolder(client, DeviceInstanceFor(client, label, 0));
    Cari::Tree request;
    request.AddFile(port + "/csr-" + label + ".pem", ReqPem(csr.get()));
    request.AddFile(port + "/key-" + label + ".pem", KeyPem(key.get()));
    std::string error;
    std::string text = ReplaceAll(CSR_DIR_README, "%LABEL%", label);
    text = ReplaceAll(text, "%CSR%", port + "/csr-" + label + ".pem");
    text = ReplaceAll(text, "%KEY%", port + "/key-" + label + ".pem");
    text = ReplaceAll(text, "%SUBJECT%", CN_PREFIX + label);
    if (!Cari::WriteToDir(request, dir.string(), &error) ||
        !WriteFile(dir / (label + "-cari-request.zip"), Cari::WriteZip(request)) || !WriteFile(dir / "readme.txt", text)) {
        fprintf(stderr, "Error: %s\n", error.empty() ? "could not write the request" : error.c_str());
        return false;
    }
    printf("Wrote a new key and a CARI certificate request for \"%s\" in \"%s\":\n", label.c_str(),
           dir.string().c_str());
    printf("  %s/csr-%s.pem   the request\n", port.c_str(), label.c_str());
    printf("  %s/key-%s.pem   PRIVATE - keep it on this device\n", port.c_str(), label.c_str());
    printf("  %s-cari-request.zip   the same as a CARI file - send this to whoever runs the hub\n", label.c_str());
    printf("The hub signs it with:  --sign-csr %s-cari-request.zip   (or the set-up guide's \"Sign\")\n",
           label.c_str());
    return true;
}

bool SignClientCsr(const std::string& certDirArg, uint32_t hubDeviceInstance, const std::string& input,
                   const ClientOptions& client) {
    const CertLayout::HubCertPaths paths = CertLayout::ResolveHubCertPaths(certDirArg, hubDeviceInstance);
    fs::path inputPath(input);
    std::error_code ec;

    // A --generate-csr folder (clients/<label>/, or a file inside it): sign
    // that folder's tree in place.
    fs::path folder;
    for (fs::path p = fs::is_directory(inputPath, ec) ? inputPath : inputPath.parent_path(); !p.empty();
         p = p.parent_path()) {
        if (fs::is_directory(p / "cert1", ec) && fs::equivalent(p.parent_path(), paths.clientsDir, ec)) {
            folder = p;
            break;
        }
        if (p == p.parent_path()) {
            break;
        }
    }
    std::string error;
    std::vector<SignedItem> items;
    Cari::Tree request;
    Cari::Tree response;

    if (!folder.empty() && (fs::is_directory(inputPath, ec) || inputPath.extension() == ".pem")) {
        const std::string label = client.label.empty() ? folder.filename().string() : client.label;
        if (!Cari::ReadFromDir(folder.string(), &request, &error) ||
            !SignCariTree(paths, request, &response, &items, &error)) {
            fprintf(stderr, "Error: %s\n", error.c_str());
            return false;
        }
        printf("Signed the CARI request in \"%s\" with the existing CA:\n", folder.string().c_str());
        PrintItems(items);
        std::string written;
        if (!WriteClientFolder(paths, label, response, DefaultHubUri(client), &written, &error)) {
            fprintf(stderr, "Error: %s\n", error.c_str());
            return false;
        }
        printf("Done. %s holds the device's CARI response (cert1/, %s-cari-response.zip) and tool files.\n",
               written.c_str(), label.c_str());
        return true;
    }

    const std::string bytes = ReadFile(inputPath);
    if (bytes.empty()) {
        fprintf(stderr, "Error: could not read \"%s\".\n", input.c_str());
        return false;
    }

    // A CARI request zip: the response goes next to it.
    if (bytes.compare(0, 4, "PK\x03\x04") == 0) {
        if (!Cari::ReadZip(bytes, &request, &error) || !SignCariTree(paths, request, &response, &items, &error)) {
            fprintf(stderr, "Error: %s: %s\n", input.c_str(), error.c_str());
            return false;
        }
        std::string stem = inputPath.stem().string();
        const std::string suffix = "-request";
        if (stem.size() > suffix.size() && stem.compare(stem.size() - suffix.size(), suffix.size(), suffix) == 0) {
            stem.erase(stem.size() - suffix.size());
        }
        const fs::path out = inputPath.parent_path() / (stem + "-response.zip");
        if (!WriteFile(out, Cari::WriteZip(response))) {
            return false;
        }
        printf("Signed the CARI request \"%s\" with the existing CA:\n", input.c_str());
        PrintItems(items);
        for (const SignedItem& item : items) {
            if (item.signedOk) {
                RecordSignedItem(paths, out.filename().string(), item);
            }
        }
        printf("Wrote the CARI response \"%s\"%s.\n", out.string().c_str(),
               response.Has("cert1/errors.txt") ? " - with errors.txt for the refused requests" : "");
        bool allSigned = true;
        for (const SignedItem& item : items) {
            allSigned = allSigned && item.signedOk;
        }
        return allSigned;
    }

    // A bare CSR: wrapped in a one-device request, answered as clients/<label>/.
    const std::string label = NextClientLabel(certDirArg, client);
    if (!CheckLabel(label)) {
        return false;
    }
    const fs::path dir = fs::path(paths.clientsDir) / label;
    if (fs::exists(dir / "cert1")) {
        fprintf(stderr, "Error: \"%s\" already has a certificate - not overwriting it. Use another --cert-label.\n",
                dir.string().c_str());
        return false;
    }
    if (!BareCsrToRequest(bytes, client, label, &request, &error) ||
        !SignCariTree(paths, request, &response, &items, &error)) {
        fprintf(stderr, "Error: %s\n", error.c_str());
        return false;
    }
    if (items.empty() || !items[0].signedOk) {
        fprintf(stderr, "Error: %s\n", items.empty() ? "nothing signed" : items[0].error.c_str());
        return false;
    }
    printf("Signed \"%s\" with the existing CA in \"%s\":\n", input.c_str(), certDirArg.c_str());
    PrintItems(items);
    std::string written;
    if (!WriteClientFolder(paths, label, response, DefaultHubUri(client), &written, &error)) {
        fprintf(stderr, "Error: %s\n", error.c_str());
        return false;
    }
    printf("Done. Send %s to the device's owner: opr-%s.pem goes with the private key the device made\n"
           "with its request. The running hub already trusts it - no restart needed.\n", written.c_str(),
           label.c_str());
    return true;
}

bool MigrateCertificates(const std::string& certDirArg, uint32_t hubDeviceInstance) {
    const CertLayout::HubCertPaths from = CertLayout::ResolveHubCertPaths(certDirArg, hubDeviceInstance);
    if (from.kind == CertLayout::Kind::Cari) {
        fprintf(stderr, "Error: \"%s\" already uses the CARI layout%s.\n", certDirArg.c_str(),
                fs::exists(fs::path(certDirArg) / "cert1") ? " (cert1/ exists)" : " or has no certificates");
        return false;
    }
    const CertLayout::HubCertPaths to = CertLayout::CariHubCertPaths(certDirArg, hubDeviceInstance);
    struct Copy {
        std::string from;
        std::string to;
        bool required;
        bool isPrivate;
    };
    const Copy copies[] = {
        {from.operationalCertificate, to.operationalCertificate, true, false},
        {from.privateKey, to.privateKey, true, true},
        {from.certificateSigningRequest, to.certificateSigningRequest, false, false},
        {from.issuerCertificate1, to.issuerCertificate1, true, false},
        {from.issuerCertificate2, to.issuerCertificate2, false, false},
        {from.pendingPrivateKey, to.pendingPrivateKey, false, true},
        {from.caPrivateKey, to.caPrivateKey, false, true},
    };
    for (const Copy& c : copies) {
        if (c.required && !fs::exists(c.from)) {
            fprintf(stderr, "Error: \"%s\" is missing - nothing to migrate.\n", c.from.c_str());
            return false;
        }
    }
    printf("Copying the %s certificate files in \"%s\" into the CARI layout (the old files are left as they are):\n",
           from.KindName(), certDirArg.c_str());
    std::error_code ec;
    fs::create_directories(fs::path(to.certDir) / to.portFolder / "hub", ec);
    for (const Copy& c : copies) {
        if (!fs::exists(c.from)) {
            continue;
        }
        if (!WriteFile(c.to, ReadFile(c.from), c.isPrivate)) {
            return false;
        }
        printf("  %s -> %s\n", CertLayout::RelativeTo(certDirArg, c.from).c_str(),
               CertLayout::RelativeTo(certDirArg, c.to).c_str());
    }
    if (fs::exists(from.caPrivateKey) && !WriteFile(to.caCertificate, ReadFile(from.caCertificate))) {
        return false;
    }
    WriteFile(to.readme, CERT_DIR_README);
    printf("Done. The hub now uses cert1/ (restart it). Existing device folders in clients/ keep working:\n"
           "they were signed by the same CA. To go back, delete cert1/ and ca/.\n");
    return true;
}

}  // namespace CertTool
