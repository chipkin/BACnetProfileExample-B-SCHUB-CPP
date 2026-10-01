// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// cert_inspect.cpp - see cert_inspect.h.

#include "cert_inspect.h"

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <time.h>

#include <cctype>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <vector>

#include "cari.h"
#include "json_writer.h"

namespace fs = std::filesystem;

namespace CertInspect {
namespace {

struct PkeyFree { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct X509Free { void operator()(X509* p) const { X509_free(p); } };
struct ReqFree { void operator()(X509_REQ* p) const { X509_REQ_free(p); } };
struct CrlFree { void operator()(X509_CRL* p) const { X509_CRL_free(p); } };
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;
using X509Ptr = std::unique_ptr<X509, X509Free>;
using ReqPtr = std::unique_ptr<X509_REQ, ReqFree>;
using CrlPtr = std::unique_ptr<X509_CRL, CrlFree>;

struct Check {
    std::string name;
    std::string status;  // pass | warn | fail | info
    std::string detail;
    std::string fix;
};

struct Item {
    std::string kind;   // certificate | csr | private-key | encrypted-private-key | crl | pkcs12 | cari | unknown
    std::string label;
    std::vector<std::pair<std::string, std::string>> fields;
    std::vector<Check> checks;
    X509Ptr cert;
    ReqPtr req;
    PkeyPtr key;

    void Field(const std::string& name, const std::string& value) { fields.emplace_back(name, value); }
    void Add(const std::string& name, const std::string& status, const std::string& detail,
             const std::string& fix = std::string()) {
        checks.push_back({name, status, detail, fix});
    }
};

std::string ReadFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::stringstream s;
    s << f.rdbuf();
    return s.str();
}

std::string BioText(BIO* bio) {
    char* data = NULL;
    const long len = BIO_get_mem_data(bio, &data);
    std::string text(data != NULL ? data : "", len > 0 ? (size_t)len : 0);
    BIO_free(bio);
    return text;
}

std::string NameText(const X509_NAME* name) {
    BIO* bio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB);
    return BioText(bio);
}

std::string TimeText(const ASN1_TIME* t) {
    struct tm tm;
    if (t == NULL || ASN1_TIME_to_tm(t, &tm) != 1) {
        return "?";
    }
    char buf[40];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm);
    return buf;
}

// Whole days from now to `t` (negative = in the past).
int DaysFromNow(const ASN1_TIME* t, int* seconds) {
    int days = 0;
    int secs = 0;
    ASN1_TIME_diff(&days, &secs, NULL, t);
    if (seconds != nullptr) {
        *seconds = secs;
    }
    return days;
}

std::string Hex(const unsigned char* data, size_t len, const char* sep) {
    std::string out;
    char b[4];
    for (size_t i = 0; i < len; ++i) {
        snprintf(b, sizeof(b), "%02X", data[i]);
        out += (i ? sep : "") + std::string(b);
    }
    return out;
}

std::string Fingerprint(X509* cert, const EVP_MD* md) {
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    X509_digest(cert, md, buf, &len);
    return Hex(buf, len, ":");
}

std::string KeyText(EVP_PKEY* key) {
    if (key == NULL) {
        return "?";
    }
    const int type = EVP_PKEY_get_base_id(key);
    const int bits = EVP_PKEY_get_bits(key);
    if (type == EVP_PKEY_EC) {
        char group[64] = {0};
        size_t len = 0;
        EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), &len);
        const std::string g = group;
        const std::string nice = g == "prime256v1" ? "P-256" : g == "secp384r1" ? "P-384" : g == "secp521r1" ? "P-521" : g;
        return "ECDSA " + nice + " (" + g + ", " + std::to_string(bits) + "-bit)";
    }
    if (type == EVP_PKEY_RSA) {
        return "RSA " + std::to_string(bits) + "-bit";
    }
    return std::string(EVP_PKEY_get0_type_name(key) ? EVP_PKEY_get0_type_name(key) : "?") + " " +
           std::to_string(bits) + "-bit";
}

void KeyStrengthCheck(Item* item, EVP_PKEY* key) {
    const int type = EVP_PKEY_get_base_id(key);
    const int bits = EVP_PKEY_get_bits(key);
    if ((type == EVP_PKEY_EC && bits >= 256) || (type == EVP_PKEY_RSA && bits >= 2048)) {
        item->Add("Key strength", "pass", KeyText(key));
    } else {
        item->Add("Key strength", "fail", KeyText(key) + " is too weak or not supported for BACnet/SC",
                  "Make a new key: ECDSA P-256 (recommended) or RSA 2048-bit or stronger, and a new CSR for it.");
    }
}

std::string ExtensionValue(X509_EXTENSION* ext) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (X509V3_EXT_print(bio, ext, 0, 0) != 1) {
        ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
        BIO_free(bio);
        ERR_clear_error();
        return "(raw) " + Hex(ASN1_STRING_get0_data(data), (size_t)ASN1_STRING_length(data), "");
    }
    std::string text = BioText(bio);
    for (char& c : text) {
        if (c == '\n') c = ' ';
    }
    while (!text.empty() && text.back() == ' ') text.pop_back();
    return text;
}

std::string ExtensionName(X509_EXTENSION* ext) {
    const ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
    const int nid = OBJ_obj2nid(obj);
    char oid[80];
    OBJ_obj2txt(oid, sizeof(oid), obj, 1);
    const std::string name = nid != NID_undef ? OBJ_nid2ln(nid) : std::string("Extension");
    return name + " (" + oid + ")" + (X509_EXTENSION_get_critical(ext) ? ", critical" : "");
}

// The hub's issuer certificates (both slots, duplicates kept once).
std::vector<X509Ptr> HubIssuers(const CertLayout::HubCertPaths& paths) {
    std::vector<X509Ptr> out;
    for (const std::string& p : {paths.issuerCertificate1, paths.issuerCertificate2}) {
        const std::string pem = ReadFile(p);
        BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
        while (X509* c = PEM_read_bio_X509(bio, NULL, NULL, NULL)) {
            bool dup = false;
            for (const X509Ptr& existing : out) {
                dup = dup || X509_cmp(existing.get(), c) == 0;
            }
            if (dup) {
                X509_free(c);
            } else {
                out.emplace_back(c);
            }
        }
        BIO_free(bio);
        ERR_clear_error();
    }
    return out;
}

// Verifies `cert` against the hub's issuers the way TLS will (purpose: a
// device presenting a client certificate, or the hub a server one). Returns
// 0 (X509_V_OK) or the OpenSSL verify error; *text says it in words.
int VerifyAgainstHub(X509* cert, const std::vector<X509*>& untrusted, bool asServer,
                     const CertLayout::HubCertPaths& paths, bool withCrl, std::string* text) {
    X509_STORE* store = X509_STORE_new();
    for (const X509Ptr& issuer : HubIssuers(paths)) {
        X509_STORE_add_cert(store, issuer.get());
    }
    if (withCrl) {
        const std::string crlPem = ReadFile(paths.revocationList);
        BIO* bio = BIO_new_mem_buf(crlPem.data(), (int)crlPem.size());
        while (X509_CRL* crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL)) {
            X509_STORE_add_crl(store, crl);
            X509_CRL_free(crl);
        }
        BIO_free(bio);
        ERR_clear_error();
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    }
    STACK_OF(X509)* chain = sk_X509_new_null();
    for (X509* c : untrusted) {
        sk_X509_push(chain, c);
    }
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, chain);
    X509_STORE_CTX_set_purpose(ctx, asServer ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT);
    const int ok = X509_verify_cert(ctx);
    const int err = ok == 1 ? X509_V_OK : X509_STORE_CTX_get_error(ctx);
    *text = X509_verify_cert_error_string(err);
    X509_STORE_CTX_free(ctx);
    sk_X509_free(chain);
    X509_STORE_free(store);
    ERR_clear_error();
    return err;
}

std::string VerifyFix(int err) {
    switch (err) {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            return "This certificate was not signed by a CA this hub trusts. Have the hub's CA sign the device's CSR "
                   "(the set-up guide's Sign, or --sign-csr), or add its CA to the hub as an issuer (File 4 / POST "
                   "/certs/issuer2).";
        case X509_V_ERR_CERT_HAS_EXPIRED:
            return "The certificate has expired. Sign a new one from the device's CSR.";
        case X509_V_ERR_CERT_NOT_YET_VALID:
            return "The certificate is not valid yet - check the clock on this computer and on the device.";
        case X509_V_ERR_INVALID_PURPOSE:
            return "The certificate's Extended Key Usage doesn't allow this use. A device needs clientAuth; a hub "
                   "needs serverAuth and clientAuth. Sign a new one (the hub's signing adds the right usages).";
        case X509_V_ERR_CERT_REVOKED:
            return "The certificate is on the hub's revocation list (issuer-crl.pem). Issue a new one.";
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            return "issuer-crl.pem exists but has no CRL from this certificate's issuer, so the hub refuses it. Add "
                   "that CA's CRL to the file, or remove the file.";
        case X509_V_ERR_CRL_HAS_EXPIRED:
            return "The CRL in issuer-crl.pem is past its next-update date. Publish a fresh CRL.";
        default:
            return "See the OpenSSL error above.";
    }
}

void CertificateFields(Item* item, X509* cert) {
    item->Field("Subject", NameText(X509_get_subject_name(cert)));
    item->Field("Issuer", NameText(X509_get_issuer_name(cert)));
    BIGNUM* bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), NULL);
    char* serial = BN_bn2hex(bn);
    item->Field("Serial number", serial ? serial : "?");
    OPENSSL_free(serial);
    BN_free(bn);
    item->Field("Version", "v" + std::to_string(X509_get_version(cert) + 1));
    int secs = 0;
    const int left = DaysFromNow(X509_get0_notAfter(cert), &secs);
    item->Field("Valid from", TimeText(X509_get0_notBefore(cert)));
    item->Field("Valid until", TimeText(X509_get0_notAfter(cert)) + " (" +
                                   (left >= 0 ? std::to_string(left) + " days left" : "expired " + std::to_string(-left) + " days ago") + ")");
    item->Field("Public key", KeyText(X509_get0_pubkey(cert)));
    item->Field("Signature algorithm", OBJ_nid2ln(X509_get_signature_nid(cert)));
    item->Field("SHA-256 fingerprint", Fingerprint(cert, EVP_sha256()));
    item->Field("SHA-1 fingerprint", Fingerprint(cert, EVP_sha1()));
    for (int i = 0; i < X509_get_ext_count(cert); ++i) {
        X509_EXTENSION* ext = X509_get_ext(cert, i);
        item->Field(ExtensionName(ext), ExtensionValue(ext));
    }
}

void CertificateChecks(Item* item, X509* cert, const std::vector<X509*>& untrusted, bool isHubCertificate,
                       const CertLayout::HubCertPaths& paths) {
    const bool isCa = X509_check_ca(cert) != 0;
    const std::vector<X509Ptr> issuers = HubIssuers(paths);
    if (isCa) {
        bool isHubIssuer = false;
        for (const X509Ptr& i : issuers) {
            isHubIssuer = isHubIssuer || X509_cmp(i.get(), cert) == 0;
        }
        item->Add("Role", "info", "a CA (issuer) certificate - it signs other certificates");
        item->Add("One of this hub's issuers", isHubIssuer ? "pass" : "info",
                  isHubIssuer ? "the hub trusts devices this CA signed (Issuer_Certificate_Files)"
                              : "the hub does not trust this CA",
                  isHubIssuer ? "" : "To accept devices it signed, add it as the hub's second issuer (File 4 or POST "
                                     "/certs/issuer2), then ReinitializeDevice ACTIVATE_CHANGES.");
    } else {
        std::string text;
        const int err = VerifyAgainstHub(cert, untrusted, isHubCertificate, paths, false, &text);
        if (issuers.empty()) {
            item->Add("Signed by this hub's CA", "warn", "the hub has no issuer certificate to check against",
                      "Generate certificates (--generate-certs) or install the hub's issuer (cert1/issuer/iss-1.pem).");
        } else if (err == X509_V_OK) {
            item->Add("Signed by this hub's CA", "pass",
                      std::string("chains to the hub's issuer, with the usage a ") +
                          (isHubCertificate ? "hub" : "device") + " needs - the hub's TLS check will accept it");
        } else {
            item->Add("Signed by this hub's CA", "fail",
                      "OpenSSL: \"" + text + "\" (verify error " + std::to_string(err) + ")", VerifyFix(err));
        }
        if (err == X509_V_OK && fs::exists(paths.revocationList)) {
            const int crlErr = VerifyAgainstHub(cert, untrusted, isHubCertificate, paths, true, &text);
            item->Add("Not revoked (issuer-crl.pem)", crlErr == X509_V_OK ? "pass" : "fail",
                      crlErr == X509_V_OK ? "not on the revocation list" : "OpenSSL: \"" + text + "\"",
                      crlErr == X509_V_OK ? "" : VerifyFix(crlErr));
        } else if (!fs::exists(paths.revocationList)) {
            item->Add("Not revoked", "info", "the hub has no issuer-crl.pem, so revocation isn't checked");
        }
        item->Add("Not a CA certificate", "pass", "CA:FALSE - an operational certificate, as it should be");
    }

    int secs = 0;
    const int before = DaysFromNow(X509_get0_notBefore(cert), &secs);
    const int after = DaysFromNow(X509_get0_notAfter(cert), nullptr);
    if (before > 0 || (before == 0 && secs > 0)) {
        item->Add("Valid now", "fail", "not valid until " + TimeText(X509_get0_notBefore(cert)),
                  "Check the clock on the hub and on the device - one of them is behind.");
    } else if (after < 0) {
        item->Add("Valid now", "fail", "expired " + TimeText(X509_get0_notAfter(cert)),
                  "Sign a new certificate from the device's CSR.");
    } else if (after < 30) {
        item->Add("Valid now", "warn", "expires in " + std::to_string(after) + " days",
                  "Renew it soon: sign a new certificate from the same CSR.");
    } else {
        item->Add("Valid now", "pass", std::to_string(after) + " days left");
    }

    if (!isCa) {
        EXTENDED_KEY_USAGE* eku = (EXTENDED_KEY_USAGE*)X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
        bool client = eku == NULL;
        bool server = eku == NULL;
        for (int i = 0; eku != NULL && i < sk_ASN1_OBJECT_num(eku); ++i) {
            const int nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i));
            client = client || nid == NID_client_auth;
            server = server || nid == NID_server_auth;
        }
        EXTENDED_KEY_USAGE_free(eku);
        if (isHubCertificate) {
            item->Add("Extended Key Usage", client && server ? "pass" : "fail",
                      std::string("serverAuth ") + (server ? "yes" : "NO") + ", clientAuth " + (client ? "yes" : "NO"),
                      client && server ? "" : "A hub certificate needs serverAuth (devices connect to it) and clientAuth "
                                              "(it connects to other hubs).");
        } else {
            item->Add("Extended Key Usage", client ? "pass" : "fail",
                      std::string("clientAuth ") + (client ? "yes" : "NO") + (server ? ", serverAuth yes" : ""),
                      client ? "" : "A device certificate needs clientAuth. Sign a new one from its CSR here.");
        }
        ASN1_BIT_STRING* ku = (ASN1_BIT_STRING*)X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
        if (ku != NULL) {
            const bool digitalSignature = ASN1_BIT_STRING_get_bit(ku, 0) != 0;
            item->Add("Key Usage", digitalSignature ? "pass" : "fail",
                      digitalSignature ? "digitalSignature" : "no digitalSignature",
                      digitalSignature ? "" : "TLS 1.3 needs digitalSignature. Sign a new certificate.");
            ASN1_BIT_STRING_free(ku);
        }
    }
    ERR_clear_error();
    KeyStrengthCheck(item, X509_get0_pubkey(cert));
}

void CsrFieldsAndChecks(Item* item, X509_REQ* req) {
    item->Field("Subject", NameText(X509_REQ_get_subject_name(req)));
    EVP_PKEY* key = X509_REQ_get0_pubkey(req);
    item->Field("Public key", KeyText(key));
    item->Field("Signature algorithm", OBJ_nid2ln(X509_REQ_get_signature_nid(req)));
    STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(req);
    for (int i = 0; exts != NULL && i < sk_X509_EXTENSION_num(exts); ++i) {
        X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
        item->Field("Requested: " + ExtensionName(ext), ExtensionValue(ext));
    }
    const bool hasExtensions = exts != NULL && sk_X509_EXTENSION_num(exts) > 0;
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    ERR_clear_error();

    const bool signatureOk = key != NULL && X509_REQ_verify(req, key) == 1;
    ERR_clear_error();
    item->Field("Signature", signatureOk ? "valid" : "INVALID");
    item->Add("Signature", signatureOk ? "pass" : "fail",
              signatureOk ? "made with the private key of the public key above - the requester holds that key"
                          : "the request's signature does not verify",
              signatureOk ? "" : "The CSR is damaged, or wasn't made with its own key. Make a new CSR on the device.");
    if (key != NULL) {
        KeyStrengthCheck(item, key);
    }
    const bool hasSubject = X509_NAME_entry_count(X509_REQ_get_subject_name(req)) > 0;
    item->Add("Subject", hasSubject ? "pass" : "fail",
              hasSubject ? "the certificate will carry this subject" : "the subject is empty",
              hasSubject ? "" : "Give the CSR a subject, e.g. CN=<device name>, so the hub's log can name the device.");
    if (hasExtensions) {
        item->Add("Requested extensions", "info",
                  "the hub's CA ignores these: a device certificate gets 825 days, digitalSignature, EKU clientAuth "
                  "(plus serverAuth on a CARI hub/ port)");
    }
}

// Every PEM block in `text`, as (type name, DER bytes).
std::vector<std::pair<std::string, std::string>> PemBlocks(const std::string& text) {
    std::vector<std::pair<std::string, std::string>> blocks;
    BIO* bio = BIO_new_mem_buf(text.data(), (int)text.size());
    for (;;) {
        char* name = NULL;
        char* header = NULL;
        unsigned char* data = NULL;
        long len = 0;
        if (PEM_read_bio(bio, &name, &header, &data, &len) != 1) {
            break;
        }
        const bool encryptedLegacy = header != NULL && std::string(header).find("ENCRYPTED") != std::string::npos;
        blocks.emplace_back(std::string(name) + (encryptedLegacy ? " (ENCRYPTED)" : ""),
                            std::string((const char*)data, (size_t)len));
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
    }
    BIO_free(bio);
    ERR_clear_error();
    return blocks;
}

void AddKeyItem(std::vector<Item>* items, EVP_PKEY* key, const std::string& label) {
    Item item;
    item.kind = "private-key";
    item.label = label;
    item.Field("Key", KeyText(key));
    item.Add("Private", "warn", "this is a private key: anyone who has it can pose as its device",
             "Keep it on its device. The hub didn't store it - but don't upload a production key to any tool.");
    KeyStrengthCheck(&item, key);
    EVP_PKEY_up_ref(key);
    item.key.reset(key);
    items->push_back(std::move(item));
}

// One DER or PEM block of known type -> an item.
void AddBlock(std::vector<Item>* items, const std::string& type, const std::string& der, const std::string& label,
              const CertLayout::HubCertPaths& paths, bool isHubCertificate) {
    const unsigned char* p = (const unsigned char*)der.data();
    if (type == "CERTIFICATE" || type == "TRUSTED CERTIFICATE") {
        X509Ptr cert(d2i_X509(NULL, &p, (long)der.size()));
        Item item;
        item.kind = "certificate";
        item.label = label;
        if (!cert) {
            item.kind = "unknown";
            item.Add("Parses", "fail", "a CERTIFICATE block that OpenSSL can't read", "The file is damaged.");
        } else {
            CertificateFields(&item, cert.get());
            item.cert = std::move(cert);
        }
        items->push_back(std::move(item));
    } else if (type == "CERTIFICATE REQUEST" || type == "NEW CERTIFICATE REQUEST") {
        ReqPtr req(d2i_X509_REQ(NULL, &p, (long)der.size()));
        Item item;
        item.kind = "csr";
        item.label = label;
        if (!req) {
            item.kind = "unknown";
            item.Add("Parses", "fail", "a CERTIFICATE REQUEST block that OpenSSL can't read", "The file is damaged.");
        } else {
            CsrFieldsAndChecks(&item, req.get());
            item.req = std::move(req);
        }
        items->push_back(std::move(item));
    } else if (type == "ENCRYPTED PRIVATE KEY" || type.find("(ENCRYPTED)") != std::string::npos) {
        Item item;
        item.kind = "encrypted-private-key";
        item.label = label;
        item.Field("Key", "encrypted (password-protected) - its contents can't be shown without the password");
        item.Add("Readable", "info", "a password-protected private key",
                 "The hub can use one: it asks for the password once at start-up, or reads sc-key-password from "
                 "its config file.");
        items->push_back(std::move(item));
    } else if (type.find("PRIVATE KEY") != std::string::npos) {
        PkeyPtr key(d2i_AutoPrivateKey(NULL, &p, (long)der.size()));
        if (key) {
            AddKeyItem(items, key.get(), label);
        }
    } else if (type == "X509 CRL") {
        CrlPtr crl(d2i_X509_CRL(NULL, &p, (long)der.size()));
        Item item;
        item.kind = "crl";
        item.label = label;
        if (crl) {
            item.Field("Issuer", NameText(X509_CRL_get_issuer(crl.get())));
            item.Field("Last update", TimeText(X509_CRL_get0_lastUpdate(crl.get())));
            item.Field("Next update", TimeText(X509_CRL_get0_nextUpdate(crl.get())));
            STACK_OF(X509_REVOKED)* revoked = X509_CRL_get_REVOKED(crl.get());
            item.Field("Revoked certificates", std::to_string(revoked ? sk_X509_REVOKED_num(revoked) : 0));
            const ASN1_TIME* next = X509_CRL_get0_nextUpdate(crl.get());
            const bool current = next == NULL || DaysFromNow(next, nullptr) >= 0;
            item.Add("Current", current ? "pass" : "fail", current ? "before its next-update date" : "past its next-update date",
                     current ? "" : "Publish a fresh CRL; while this one is installed the hub refuses every device "
                                    "from its issuer.");
        }
        items->push_back(std::move(item));
    } else {
        Item item;
        item.kind = "unknown";
        item.label = label;
        item.Field("PEM block", type);
        item.Add("Recognised", "info", "a \"" + type + "\" block - not a certificate, CSR, key or CRL");
        items->push_back(std::move(item));
    }
    (void)paths;
    (void)isHubCertificate;
}

// Inspects one file's bytes (PEM, DER or PKCS#12) into items.
void InspectBytes(std::vector<Item>* items, const std::string& bytes, const std::string& label,
                  const CertLayout::HubCertPaths& paths, bool isHubCertificate) {
    if (bytes.find("-----BEGIN") != std::string::npos) {
        const auto blocks = PemBlocks(bytes);
        int n = 0;
        for (const auto& b : blocks) {
            AddBlock(items, b.first, b.second,
                     blocks.size() > 1 ? label + " (block " + std::to_string(++n) + ": " + b.first + ")" : label, paths,
                     isHubCertificate);
        }
        if (blocks.empty()) {
            Item item;
            item.kind = "unknown";
            item.label = label;
            item.Add("Parses", "fail", "it has a -----BEGIN line but no PEM block OpenSSL can read",
                     "The file is damaged or was edited - get a fresh copy.");
            items->push_back(std::move(item));
        }
        return;
    }
    // DER: try each kind.
    const unsigned char* p = (const unsigned char*)bytes.data();
    if (X509* c = d2i_X509(NULL, &p, (long)bytes.size())) {
        X509_free(c);
        AddBlock(items, "CERTIFICATE", bytes, label + " (DER)", paths, isHubCertificate);
        return;
    }
    p = (const unsigned char*)bytes.data();
    if (X509_REQ* r = d2i_X509_REQ(NULL, &p, (long)bytes.size())) {
        X509_REQ_free(r);
        AddBlock(items, "CERTIFICATE REQUEST", bytes, label + " (DER)", paths, isHubCertificate);
        return;
    }
    p = (const unsigned char*)bytes.data();
    if (PKCS12* p12 = d2i_PKCS12(NULL, &p, (long)bytes.size())) {
        EVP_PKEY* key = NULL;
        X509* cert = NULL;
        STACK_OF(X509)* ca = NULL;
        const bool opened = PKCS12_parse(p12, "", &key, &cert, &ca) == 1 || PKCS12_parse(p12, NULL, &key, &cert, &ca) == 1;
        PKCS12_free(p12);
        ERR_clear_error();
        Item item;
        item.kind = "pkcs12";
        item.label = label + " (PKCS#12 / .pfx)";
        item.Add("Opens with an empty password", opened ? "pass" : "fail",
                 opened ? "YABE and the hub's own .pfx files use an empty password" : "it needs a password",
                 opened ? "" : "The inspector only opens .pfx files with an empty password. Export the certificate "
                               "and key as PEM instead.");
        items->push_back(std::move(item));
        if (opened) {
            if (cert != NULL) {
                const std::string der = [&] {
                    unsigned char* d = NULL;
                    const int l = i2d_X509(cert, &d);
                    std::string s((const char*)d, l > 0 ? (size_t)l : 0);
                    OPENSSL_free(d);
                    return s;
                }();
                AddBlock(items, "CERTIFICATE", der, label + ": certificate", paths, isHubCertificate);
            }
            for (int i = 0; ca != NULL && i < sk_X509_num(ca); ++i) {
                unsigned char* d = NULL;
                const int l = i2d_X509(sk_X509_value(ca, i), &d);
                AddBlock(items, "CERTIFICATE", std::string((const char*)d, l > 0 ? (size_t)l : 0),
                         label + ": chain certificate " + std::to_string(i + 1), paths, false);
                OPENSSL_free(d);
            }
            if (key != NULL) {
                AddKeyItem(items, key, label + ": private key");
            }
        }
        EVP_PKEY_free(key);
        X509_free(cert);
        sk_X509_pop_free(ca, X509_free);
        return;
    }
    p = (const unsigned char*)bytes.data();
    if (EVP_PKEY* k = d2i_AutoPrivateKey(NULL, &p, (long)bytes.size())) {
        AddKeyItem(items, k, label + " (DER)");
        EVP_PKEY_free(k);
        return;
    }
    ERR_clear_error();
    Item item;
    item.kind = "unknown";
    item.label = label;
    std::string what = "not a certificate, CSR, private key, .pfx or CARI zip";
    if (bytes.size() >= 2 && (unsigned char)bytes[0] == 0xFF && (unsigned char)bytes[1] == 0xFE) {
        what += " (it looks like UTF-16 text - save it as UTF-8 or ANSI)";
    }
    item.Add("Recognised", "fail", what + " (" + std::to_string(bytes.size()) + " bytes)",
             "Certificates and CSRs are PEM (text starting with -----BEGIN) or DER (binary). A CARI file is a .zip with "
             "a cert1/ folder.");
    items->push_back(std::move(item));
}

// Runs the checks that need all items: certificates against the hub, keys
// against certificates and CSRs in the same upload.
void CrossChecks(std::vector<Item>* items, const CertLayout::HubCertPaths& paths, bool isHubCertificate) {
    std::vector<X509*> chain;
    for (Item& item : *items) {
        if (item.cert) {
            chain.push_back(item.cert.get());
        }
    }
    for (Item& item : *items) {
        if (item.cert) {
            std::vector<X509*> others;
            for (X509* c : chain) {
                if (c != item.cert.get()) others.push_back(c);
            }
            CertificateChecks(&item, item.cert.get(), others, isHubCertificate, paths);
        }
    }
    for (Item& item : *items) {
        if (!item.key) continue;
        bool compared = false;
        for (Item& other : *items) {
            EVP_PKEY* pub = other.cert ? X509_get0_pubkey(other.cert.get()) : other.req ? X509_REQ_get0_pubkey(other.req.get()) : nullptr;
            if (pub == nullptr || (other.cert && X509_check_ca(other.cert.get()))) continue;
            compared = true;
            const bool match = EVP_PKEY_eq(item.key.get(), pub) == 1;
            item.Add("Matches " + other.label, match ? "pass" : "fail",
                     match ? "this key belongs to it" : "this key is NOT the one in it",
                     match ? "" : "The key and the certificate/CSR are from different sets. Find the key that was made "
                                  "with this CSR.");
            other.Add("Matches the private key " + item.label, match ? "pass" : "fail",
                      match ? "the key in the same upload belongs to it" : "the key in the same upload is a different one");
        }
        if (!compared) {
            item.Add("Matches a certificate", "info", "no certificate or CSR in the same upload to compare with");
        }
    }
    ERR_clear_error();
}

std::string ItemsJson(const std::vector<Item>& items) {
    Json::Array arr;
    for (const Item& item : items) {
        Json::Array fields;
        for (const auto& f : item.fields) {
            fields.Add(Json::Object().Add("name", Json::Str(f.first)).Add("value", Json::Str(f.second)).Text());
        }
        Json::Array checks;
        for (const Check& c : item.checks) {
            checks.Add(Json::Object()
                           .Add("name", Json::Str(c.name))
                           .Add("status", Json::Str(c.status))
                           .Add("detail", Json::Str(c.detail))
                           .Add("fix", Json::Str(c.fix))
                           .Text());
        }
        arr.Add(Json::Object()
                    .Add("kind", Json::Str(item.kind))
                    .Add("label", Json::Str(item.label))
                    .Add("fields", fields.Text())
                    .Add("checks", checks.Text())
                    .Text());
    }
    return arr.Text();
}

std::string Summary(const std::vector<Item>& items, const std::string& detected) {
    int fails = 0;
    int warns = 0;
    for (const Item& item : items) {
        for (const Check& c : item.checks) {
            fails += c.status == "fail";
            warns += c.status == "warn" && item.kind != "private-key";
        }
    }
    (void)detected;
    if (fails > 0) {
        return std::to_string(fails) + " problem" + (fails == 1 ? "" : "s") + " found - see the red checks below, each "
               "says what to do.";
    }
    if (warns > 0) {
        return "Looks usable, with " + std::to_string(warns) + " warning" + (warns == 1 ? "" : "s") + ".";
    }
    return "All checks passed.";
}

}  // namespace

namespace {

// Everything InspectJson()/InspectText() report: the items, what the file is,
// and (for a CARI zip) the tree's JSON.
void BuildItems(const std::string& bytes, const std::string& fileName, const CertLayout::HubCertPaths& paths,
                std::vector<Item>* itemsOut, std::string* detectedOut, std::string* cariJson) {
    std::vector<Item>& items = *itemsOut;
    std::string& detected = *detectedOut;
    const std::string label = fileName.empty() ? std::string("the file") : fileName;

    if (bytes.compare(0, 4, "PK\x03\x04") == 0) {
        Cari::Tree tree;
        std::string error;
        Json::Object cari;
        if (!Cari::ReadZip(bytes, &tree, &error)) {
            Item item;
            item.kind = "cari";
            item.label = label;
            item.Add("Readable zip", "fail", error, "A CARI file is a plain zip (stored or deflate) of a cert1/ folder.");
            items.push_back(std::move(item));
            detected = "a zip file that can't be read as CARI";
        } else {
            std::vector<std::string> problems;
            const bool valid = Cari::Validate(tree, true, &problems);
            bool isResponse = false;
            for (const auto& f : tree.files) {
                isResponse = isResponse || f.first.find("/opr-") != std::string::npos ||
                             f.first.compare(0, 13, "cert1/issuer/") == 0;
            }
            detected = std::string("a CARI ") + (isResponse ? "response" : "request") + " (ANSI/ASHRAE 135-2024 Annex AA.2)";
            Json::Array files;
            for (const std::string& folder : tree.folders) {
                files.Add(Json::Str(folder + "/"));
            }
            for (const auto& f : tree.files) {
                files.Add(Json::Str(f.first + " (" + std::to_string(f.second.size()) + " bytes)"));
            }
            Json::Array probs;
            for (const std::string& p : problems) {
                probs.Add(Json::Str(p));
            }
            const std::vector<Cari::CsrEntry> csrs = Cari::ListCsrs(tree);
            cari.Add("valid", Json::Bool(valid))
                .Add("response", Json::Bool(isResponse))
                .Add("csrCount", Json::Num((int64_t)csrs.size()))
                .Add("files", files.Text())
                .Add("problems", probs.Text());
            Item summary;
            summary.kind = "cari";
            summary.label = label;
            summary.Field("Devices / CSRs", std::to_string(csrs.size()) + " CSR(s)");
            for (const Cari::CsrEntry& c : csrs) {
                summary.Field(c.deviceFolder + "/" + c.portFolder,
                              "csr-" + c.name + ".pem" + (tree.Has(c.oprPath) ? " + opr-" + c.name + ".pem" : "") +
                                  (c.keyPath.empty() ? "" : " + key-" + c.name + ".pem") +
                                  (c.isHubPort ? " (hub port)" : "") + (c.isRouter ? " (router)" : ""));
            }
            if (tree.Has("cert1/errors.txt")) {
                summary.Field("errors.txt", tree.files.at("cert1/errors.txt"));
            }
            if (tree.Has("cert1/request-notes.txt")) {
                summary.Field("request-notes.txt", tree.files.at("cert1/request-notes.txt"));
            }
            if (tree.Has("cert1/response-notes.txt")) {
                summary.Field("response-notes.txt", tree.files.at("cert1/response-notes.txt"));
            }
            summary.Add("CARI layout", valid ? "pass" : "fail",
                        valid ? "every file and folder has a name Annex AA.2 allows" : problems.front(),
                        valid ? "" : "Fix the names in the zip (see all problems below) and make it again.");
            if (csrs.empty()) {
                summary.Add("Has CSRs", "fail", "no csr-<name>.pem in any port folder",
                            "Each device-<instance>/port-<id>/ folder needs a csr-<name>.pem.");
            }
            items.push_back(std::move(summary));
            for (const auto& f : tree.files) {
                const std::string name = fs::path(f.first).filename().string();
                if (name.size() > 4 && name.compare(name.size() - 4, 4, ".pem") == 0) {
                    InspectBytes(&items, f.second, f.first, paths, false);
                }
            }
        }
        CrossChecks(&items, paths, false);
        *cariJson = cari.Text();
    } else {
        InspectBytes(&items, bytes, label, paths, false);
        CrossChecks(&items, paths, false);
        std::vector<std::string> kinds;
        for (const Item& item : items) {
            kinds.push_back(item.kind);
        }
        if (items.size() == 1) {
            const std::string& k = items[0].kind;
            detected = k == "certificate" ? (items[0].cert && X509_check_ca(items[0].cert.get()) ? "a CA (issuer) certificate"
                                                                                               : "a certificate")
                     : k == "csr" ? "a certificate signing request (CSR)"
                     : k == "private-key" ? "a private key"
                     : k == "encrypted-private-key" ? "a password-protected private key"
                     : k == "crl" ? "a certificate revocation list"
                     : "an unrecognised file";
        } else {
            detected = std::to_string(items.size()) + " items";
        }
    }
}

}  // namespace

std::string InspectJson(const std::string& bytes, const std::string& fileName, const CertLayout::HubCertPaths& paths) {
    if (bytes.empty()) {
        return Json::Object()
            .Add("detected", Json::Str("nothing"))
            .Add("summary", Json::Str("the upload was empty - choose a file or paste its text"))
            .Add("items", "[]")
            .Text();
    }
    std::vector<Item> items;
    std::string detected;
    std::string cari;
    BuildItems(bytes, fileName, paths, &items, &detected, &cari);
    Json::Object out;
    if (!cari.empty()) {
        out.Add("cari", cari);
    }
    out.Add("detected", Json::Str(detected))
        .Add("summary", Json::Str(Summary(items, detected)))
        .Add("items", ItemsJson(items));
    return out.Text();
}

std::string InspectText(const std::string& bytes, const std::string& fileName, const CertLayout::HubCertPaths& paths,
                        bool* anyFailure) {
    std::vector<Item> items;
    std::string detected;
    std::string cari;
    BuildItems(bytes, fileName, paths, &items, &detected, &cari);
    std::string t = (fileName.empty() ? std::string("The file") : fileName) + " is " + detected + ". " +
                    Summary(items, detected) + "\n";
    *anyFailure = false;
    for (const Item& item : items) {
        t += "\n== " + item.label + " (" + item.kind + ")\n";
        for (const Check& c : item.checks) {
            std::string status = c.status;
            for (char& ch : status) ch = (char)toupper((unsigned char)ch);
            t += "  [" + status + "] " + c.name + ": " + c.detail + "\n";
            if (!c.fix.empty() && c.status != "pass") {
                t += "         -> " + c.fix + "\n";
            }
            *anyFailure = *anyFailure || c.status == "fail";
        }
        for (const auto& f : item.fields) {
            t += "    " + f.first + ": " + f.second + "\n";
        }
    }
    return t;
}

std::string CertificateFileJson(const std::string& path, const std::string& label, bool isHubCertificate,
                                const CertLayout::HubCertPaths& paths) {
    std::vector<Item> items;
    const std::string bytes = ReadFile(path);
    if (bytes.empty()) {
        Item item;
        item.kind = "missing";
        item.label = label;
        item.Add("Present", "fail", "\"" + path + "\" is missing or empty",
                 "Run BACnetExampleBSCHUB --generate-certs, or put the certificate there.");
        items.push_back(std::move(item));
    } else {
        InspectBytes(&items, bytes, label, paths, isHubCertificate);
        CrossChecks(&items, paths, isHubCertificate);
    }
    return ItemsJson(items);
}

}  // namespace CertInspect
