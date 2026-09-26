// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// cert_tool.cpp - see cert_tool.h for what this does and why.

#include "cert_tool.h"

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

#include <filesystem>
#include <memory>
#include <regex>
#include <set>
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
const char* const MANIFEST_FILE = "certificates.txt";
const char* const README_FILE = "readme.txt";

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

X509Ptr MakeCertificate(Role role, const std::string& commonName, EVP_PKEY* subjectKey,
                        const Credential* issuer, const std::string& hubSubjectAltName = std::string()) {
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
                                hubSubjectAltName.empty() ? HubSubjectAltName(std::string()) : hubSubjectAltName);
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

// Writes `cert` in DER (binary) form - the ".cer" Windows tools expect.
bool WriteDer(const fs::path& path, X509* cert) {
    FILE* f = fopen(path.string().c_str(), "wb");
    if (f == NULL) {
        fprintf(stderr, "Error: could not create \"%s\".\n", path.string().c_str());
        return false;
    }
    const bool ok = i2d_X509_fp(f, cert) == 1;
    fclose(f);
    if (!ok) {
        PrintOpenSslError("could not write DER data");
    }
    return ok;
}

// Writes a PKCS#12 (.pfx) bundle: `cert`, its private `key`, and `issuer` as
// the chain, under `friendlyName`, with an EMPTY password - YABE's BACnet/SC
// channel file has no password field. So the .pfx is as private as
// private-key.pem. 3DES and a SHA-1 MAC rather than OpenSSL 3's AES/SHA-256
// defaults, so every Windows version can load it.
bool WritePfx(const fs::path& path, EVP_PKEY* key, X509* cert, X509* issuer, const std::string& friendlyName) {
    STACK_OF(X509)* chain = sk_X509_new_null();
    sk_X509_push(chain, issuer);
    PKCS12* p12 = PKCS12_create("", friendlyName.c_str(), key, cert, chain,
                                NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                2048, -1 /* MAC set below */, 0);
    sk_X509_free(chain);  // the issuer itself stays owned by the caller
    bool ok = p12 != NULL && PKCS12_set_mac(p12, "", -1, NULL, 0, 2048, EVP_sha1()) == 1;
    FILE* f = ok ? fopen(path.string().c_str(), "wb") : NULL;
    if (ok && f == NULL) {
        fprintf(stderr, "Error: could not create \"%s\".\n", path.string().c_str());
        ok = false;
    }
    if (f != NULL) {
        ok = i2d_PKCS12_fp(f, p12) == 1;
        fclose(f);
        std::error_code ec;  // private, like private-key.pem
        fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
    }
    PKCS12_free(p12);
    if (!ok) {
        PrintOpenSslError("could not write the PKCS#12 (.pfx) file");
    }
    return ok;
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

// Path of `name` inside certDir, falling back to `legacyName` - see
// ResolveCertFile().
fs::path Resolve(const fs::path& certDir, const char* name, const char* legacyName) {
    return certDir / ResolveCertFile(certDir.string(), name, legacyName);
}

bool LoadIssuer(const fs::path& certDir, Credential* out) {
    const fs::path crtPath = Resolve(certDir, ISSUER_CERTIFICATE_FILE, LEGACY_ISSUER_CERTIFICATE_FILE);
    const fs::path keyPath = Resolve(certDir, ISSUER_PRIVATE_KEY_FILE, LEGACY_ISSUER_PRIVATE_KEY_FILE);
    FILE* f = fopen(crtPath.string().c_str(), "rb");
    if (f == NULL) {
        fprintf(stderr, "Error: \"%s\" not found. Run --generate-certs first.\n", crtPath.string().c_str());
        return false;
    }
    out->cert.reset(PEM_read_X509(f, NULL, NULL, NULL));
    fclose(f);
    f = fopen(keyPath.string().c_str(), "rb");
    if (f == NULL) {
        fprintf(stderr, "Error: \"%s\" not found. The issuer's private key is needed to sign new "
                        "client certificates.\n", keyPath.string().c_str());
        return false;
    }
    out->key.reset(PEM_read_PrivateKey(f, NULL, NULL, NULL));
    fclose(f);
    if (!out->cert || !out->key) {
        PrintOpenSslError("could not read the existing issuer certificate/key");
        return false;
    }
    if (X509_check_private_key(out->cert.get(), out->key.get()) != 1) {
        fprintf(stderr, "Error: \"%s\" does not belong to \"%s\".\n", keyPath.string().c_str(),
                crtPath.string().c_str());
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
// header the first time) and echoes it to stdout. `where` is the certificate's
// location relative to certDir, e.g. "clients/client-01/".
void RecordInManifest(const fs::path& certDir, const std::string& label, const std::string& role,
                      const std::string& where, X509* cert) {
    const fs::path manifest = certDir / MANIFEST_FILE;
    const bool isNew = !fs::exists(manifest);
    FILE* f = fopen(manifest.string().c_str(), "ab");
    if (f == NULL) {
        return;
    }
    if (isNew) {
        fprintf(f, "# Lab BACnet/SC certificates generated by BACnetExampleBSCHUB (LAB TESTING ONLY).\n"
                   "# label | role | location | serial | expires | SHA-256 fingerprint\n");
    }
    const std::string location = where.empty() ? std::string("./") : where;
    fprintf(f, "%s | %s | %s | %s | %s | %s\n", label.c_str(), role.c_str(), location.c_str(),
            SerialHex(cert).c_str(), NotAfter(cert).c_str(), Sha256Fingerprint(cert).c_str());
    fclose(f);
    printf("  %-12s %-7s %s  (expires %s)\n", label.c_str(), role.c_str(), location.c_str(),
           NotAfter(cert).c_str());
}

// readme.txt for the certificate folder: what each file is, whether it is
// private, what the BACnet standard says it is for, and how to use the set.
// Rewritten on every run so it never goes stale; the per-certificate list
// lives in certificates.txt, which this file points at.
const char* const CERT_DIR_README = R"(BACnet/SC lab certificates - generated by BACnetExampleBSCHUB
==============================================================

LAB TESTING ONLY. These certificates come from a throwaway certificate
authority made on this computer. Use your own PKI (or a real CA) for a
production installation.

This folder holds everything a BACnet/SC hub and the devices that connect to
it need to authenticate each other. BACnet/SC (ANSI/ASHRAE 135-2024 Annex AB)
runs BACnet over secure WebSockets: every connection is TLS 1.3 with mutual
authentication, so BOTH ends present a certificate, and each end accepts the
other only if that certificate was signed by an issuer it trusts.

The file names follow the Network Port object properties that carry them
(ANSI/ASHRAE 135-2024 clause 12.56). The descriptions below paraphrase the
standard; see the clauses named for the normative text.


FILES IN THIS FOLDER (the hub's own files)
------------------------------------------

operational-certificate.pem                                       PUBLIC
    The hub's operational certificate. The standard describes the
    operational certificate as the one a BACnet/SC device presents to its
    peers to identify itself when a secure connection is established.
    This is the file the Network Port's Operational_Certificate_File
    property refers to; BACnetExampleBSCHUB serves it as File 1
    ("Operational Certificate"). This certificate works as a TLS server
    (for devices connecting to the hub) and as a TLS client (when the hub
    itself dials another hub), and its Subject Alternative Name lists
    localhost, 127.0.0.1 and this computer's host name.

private-key.pem                                                   PRIVATE
    The private key that belongs to operational-certificate.pem. Only the
    hub's TLS layer reads it. It is never served over BACnet: no File object
    refers to it, and the standard has no property for it. Anyone holding
    this file can impersonate the hub. Never copy it to another device.

certificate-signing-request.pem                                   PUBLIC
    A certificate signing request (PKCS#10) for the hub's key. The
    standard's Certificate_Signing_Request_File property refers to a file
    holding the device's most recent signing request, so that a
    configuration tool can read it, have it signed by the site's own
    certificate authority, and write the resulting certificate back as the
    new operational certificate. BACnetExampleBSCHUB serves it as File 2
    ("Certificate Signing Request"). To move the hub onto your own PKI, give
    this file to your CA and install the certificate it returns as
    operational-certificate.pem.

issuer-certificate.pem                                            PUBLIC
    The certificate of the issuer (certificate authority) that signed every
    operational certificate in this set - the hub's and every client's. The
    standard's Issuer_Certificate_Files property is an array of exactly two
    file references: the issuer certificates a device uses to validate the
    certificates its peers present. BACnetExampleBSCHUB serves this file as
    File 3 ("Issuer Certificate Slot 1"). File 4 ("Issuer Certificate Slot
    2") serves issuer-certificate-2.pem once a client has written one over
    BACnet, and this same file until then. With a real PKI the two slots
    typically hold a root and an intermediate certificate. Every device that
    connects to the hub needs a copy.

issuer-private-key.pem                                            PRIVATE
    The issuer's private key. It is the only thing that can sign new
    certificates this hub will trust, so anyone who holds it can add devices
    to your BACnet/SC network. It is used only by
    "BACnetExampleBSCHUB --add-client-certs"; the running hub never reads
    it. Keep it off devices, and ideally off the network entirely.

issuer-certificate-2.pem                                          PUBLIC
    Not created by --generate-certs. Written when a client adds a second
    issuer over BACnet (clause 19.8.3 "add issuer", File 4), so devices
    signed by either issuer are accepted.

trusted-issuers.pem                                               PUBLIC
    Written by the hub at startup and after every certificate change: every
    issuer certificate from both slots. This is what TLS trusts peers
    against. Don't edit it; it's regenerated.

certificates.txt                                                  PUBLIC
    One line per certificate in this set: label, location, serial number,
    expiry date and SHA-256 fingerprint. Use the fingerprint to tell which
    certificate a peer presented in a log or packet capture.

readme.txt                                                        PUBLIC
    This file. It is rewritten each time certificates are generated.


FILES IN EACH clients/<label>/ FOLDER (one folder per connecting device)
------------------------------------------------------------------------

operational-certificate.pem                                       PUBLIC
    That device's own operational certificate (TLS client). Its subject
    Common Name is "Chipkin Example B-SCHUB <label>", so the hub's logs show
    which device connected.

private-key.pem                                                   PRIVATE
    That device's private key. It belongs on that one device only.

issuer-certificate.pem                                            PUBLIC
    A copy of this folder's issuer-certificate.pem, so the device can
    validate the hub's certificate. Load it into both of the device's
    Issuer_Certificate_Files slots (or its equivalent trust setting).

bacnetsc.config                                                   PUBLIC
    The device's BACnet/SC connection settings, ready to import into the
    CAS BACnet Explorer: role "device", the hub's primary URI, the three
    PEM files above (by file name, so keep them in the same folder) and
    hub-certificate validation turned on. The URI is the one the hub had
    when the certificates were made - this computer's IPv4 address and
    --sc-port - or whatever --cert-hub-uri said. Edit primaryHubURI (and
    failoverHubURI, if you have a second hub) if that changes.

<label>.pfx                                                       PRIVATE
    The same certificate and private key (plus the issuer) in one PKCS#12
    file, for Windows tools such as YABE. It has an EMPTY password, so it is
    as private as private-key.pem.

issuer-certificate.cer                                            PUBLIC
    issuer-certificate.pem in DER (binary) form, for Windows tools.

yabe-bacnetsc.config                                              PUBLIC
    A ready-to-use BACnet/SC channel file for YABE (Yet Another BACnet
    Explorer): the hub URI, <label>.pfx and issuer-certificate.cer, by
    absolute path. In YABE: Communication Channel -> BACnet/Secure Connect ->
    Select this file -> Start. YABE uses Windows' TLS, which can't do the
    TLS 1.3 BACnet/SC requires on Windows 10 - use Windows 11 or later.

readme.txt                                                        PUBLIC
    A short note for whoever receives that folder.


HOW TO USE THESE FILES
----------------------

1. Start the hub with this folder as its certificate directory:

       BACnetExampleBSCHUB --sc-cert-dir <this folder>

   It listens for BACnet/SC connections on wss://<this computer>:47819/
   (change the port with --sc-port).

2. Give each device that will connect to the hub its own clients/<label>/
   folder.

   CAS BACnet Explorer: import clients/<label>/bacnetsc.config. It
   already names the hub URI and the three PEM files in the same folder.

   YABE: select clients/<label>/yabe-bacnetsc.config as the BACnet/SC
   channel's configuration file (Windows 11 or later - see above).

   Any other BACnet/SC device:
     - install operational-certificate.pem and private-key.pem as its
       operational certificate and key;
     - install issuer-certificate.pem as its issuer (trusted CA)
       certificate, in both issuer slots if it has two;
     - set its primary hub URI to the primaryHubURI in bacnetsc.config
       (wss://<hub address>:47819/ by default).
   Hand each folder to one device only. Two devices sharing a certificate
   can't be told apart by the hub.

3. Need more devices? Sign more clients with the SAME issuer:

       BACnetExampleBSCHUB --sc-cert-dir <this folder> --add-client-certs 2
       BACnetExampleBSCHUB --sc-cert-dir <this folder> --add-client-certs 3 --cert-label ahu

   Numbering continues after the highest existing label. The running hub
   trusts the new certificates immediately; no restart is needed.

4. Check a certificate before installing it (any OpenSSL):

       openssl verify -CAfile issuer-certificate.pem clients/client-01/operational-certificate.pem
       openssl x509 -in clients/client-01/operational-certificate.pem -noout -subject -dates

   A certificate that fails "openssl verify" will also fail the TLS
   handshake, and the BACnet side may not say why.

5. Starting over: "--generate-certs --force" deletes this whole set,
   including clients/, and makes a new issuer. Every device then needs its
   new folder, because none of them trust the new issuer yet.


WHAT MUST STAY PRIVATE
----------------------

    private-key.pem                      (this folder, and every clients/<label>/)
    issuer-private-key.pem

Everything else is public by design: BACnet clients can read the hub's
operational certificate, signing request and issuer certificates over
AtomicReadFile.


KEY AND CERTIFICATE DETAILS
---------------------------

    Keys:          ECDSA P-256 (prime256v1), PEM (PKCS#8)
    Signatures:    SHA-256
    Issuer:        valid 10 years; CA:TRUE; keyCertSign, cRLSign
    Hub:           valid 825 days; EKU serverAuth + clientAuth
    Clients:       valid 825 days; EKU clientAuth
)";

// Short note in each clients/<label>/ folder, for whoever receives it.
const char* const CLIENT_DIR_README = R"(BACnet/SC client certificate "%LABEL%" - LAB TESTING ONLY
Generated by BACnetExampleBSCHUB for ONE device that connects to its BACnet/SC hub.

operational-certificate.pem    PUBLIC   This device's operational certificate: what it
                                        presents to the hub to identify itself
                                        (Network Port property Operational_Certificate_File,
                                        ANSI/ASHRAE 135-2024 clause 12.56). Subject CN:
                                        "Chipkin Example B-SCHUB %LABEL%".
private-key.pem                PRIVATE  This device's private key. Keep it on this device
                                        only; never serve it over BACnet.
issuer-certificate.pem         PUBLIC   The certificate authority that signed the hub's
                                        certificate. The device uses it to validate the hub
                                        (Issuer_Certificate_Files - load it into both slots).

bacnetsc.config                PUBLIC   This device's BACnet/SC connection settings: hub URI
                                        %HUBURI% and the three files above.
                                        Import it into the CAS BACnet Explorer.
%LABEL%.pfx                    PRIVATE  The certificate, private key and issuer in one PKCS#12
                                        file for Windows tools. EMPTY password - keep it as
                                        private as private-key.pem.
issuer-certificate.cer         PUBLIC   issuer-certificate.pem in DER form.
yabe-bacnetsc.config           PUBLIC   YABE's BACnet/SC channel file (hub URI, the .pfx and
                                        the .cer by absolute path). In YABE: Communication
                                        Channel -> BACnet/Secure Connect -> Select -> Start.
                                        Needs Windows 11 or later (TLS 1.3).

To connect from the CAS BACnet Explorer (https://store.chipkin.com/products/tools/cas-bacnet-explorer):
import bacnetsc.config from this folder
(keep the .pem files next to it).
From any other BACnet/SC device: install the operational certificate and key as its
operational certificate, install issuer-certificate.pem as its issuer certificate,
and set its primary hub URI to %HUBURI%.

See ../../readme.txt in the hub's certificate folder for the full description.
)";

// Writes a text file (overwriting any previous version).
bool WriteText(const fs::path& path, const std::string& text) {
    FILE* f = fopen(path.string().c_str(), "wb");
    if (f == NULL) {
        fprintf(stderr, "Error: could not create \"%s\".\n", path.string().c_str());
        return false;
    }
    fwrite(text.data(), 1, text.size(), f);
    fclose(f);
    return true;
}

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

// bacnetsc.config for one client folder: the BACnet/SC connection settings
// (this hub's URI and the folder's three PEM files, referenced by name) in the
// XML format the CAS BACnet Explorer imports. Role "device" = a BACnet/SC
// node that connects to a hub; ValidateHubCertificate makes it check the
// hub's certificate against issuer-certificate.pem.
std::string BacnetScConfig(const std::string& hubUri) {
    std::string xml;
    xml += "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    xml += "<BACnetSCConfigChannel>\n";
    xml += "    <Role>device</Role>\n";
    xml += "    <primaryHubURI>" + XmlEscape(hubUri) + "</primaryHubURI>\n";
    xml += "    <failoverHubURI></failoverHubURI>\n";
    xml += std::string("    <operationalCertificate>") + OPERATIONAL_CERTIFICATE_FILE + "</operationalCertificate>\n";
    xml += std::string("    <devicePrivateKeyFile>") + PRIVATE_KEY_FILE + "</devicePrivateKeyFile>\n";
    xml += std::string("    <issuerCertificate>") + ISSUER_CERTIFICATE_FILE + "</issuerCertificate>\n";
    xml += "    <ValidateHubCertificate>true</ValidateHubCertificate>\n";
    xml += "</BACnetSCConfigChannel>\n";
    return xml;
}

// yabe-bacnetsc.config for one client folder: YABE's BACnet/SC channel file
// (the format of BACnetSCConfig.config next to Yabe.exe). YABE resolves
// relative names against its own folder, so the files are given by absolute
// path; move the folder and re-select or edit the file.
std::string YabeConfig(const std::string& hubUri, const fs::path& pfxPath, const fs::path& issuerPath) {
    // YABE's own example writes the URI without a trailing '/'.
    std::string uri = hubUri;
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

// Refuses to write over an existing file.
bool CheckNotExisting(const std::vector<fs::path>& paths) {
    for (const fs::path& p : paths) {
        if (fs::exists(p)) {
            fprintf(stderr, "Error: \"%s\" already exists - not overwriting it.\n", p.string().c_str());
            return false;
        }
    }
    return true;
}

// Generates the hub's key, operational certificate and CSR in certDir.
bool IssueHub(const fs::path& certDir, const Credential& issuer, const std::string& hubUri) {
    const fs::path keyPath = certDir / PRIVATE_KEY_FILE;
    const fs::path crtPath = certDir / OPERATIONAL_CERTIFICATE_FILE;
    const fs::path csrPath = certDir / CERTIFICATE_SIGNING_REQUEST_FILE;
    if (!CheckNotExisting({keyPath, crtPath, csrPath})) {
        return false;
    }
    PkeyPtr key = NewP256Key();
    if (!key) {
        return false;
    }
    X509Ptr cert = MakeCertificate(Role::Hub, CN_PREFIX + std::string(HUB_LABEL), key.get(), &issuer,
                                   HubSubjectAltName(hubUri));
    if (!cert || !WritePem(keyPath, key.get(), NULL) || !WritePem(crtPath, NULL, cert.get()) ||
        !WriteCsr(csrPath, key.get(), cert.get())) {
        return false;
    }
    RecordInManifest(certDir, HUB_LABEL, "hub", "", cert.get());
    return true;
}

// Generates one client's folder: clients/<label>/ with its key, operational
// certificate and a copy of the issuer certificate - everything that device
// needs to connect to this hub.
bool IssueClient(const fs::path& certDir, const Credential& issuer, const std::string& label,
                 const std::string& hubUri) {
    const fs::path dir = certDir / CLIENTS_DIR / label;
    const fs::path keyPath = dir / PRIVATE_KEY_FILE;
    const fs::path crtPath = dir / OPERATIONAL_CERTIFICATE_FILE;
    const fs::path issuerPath = dir / ISSUER_CERTIFICATE_FILE;
    if (!CheckNotExisting({keyPath, crtPath, issuerPath})) {
        return false;
    }
    std::error_code ec;
    fs::create_directories(dir, ec);
    PkeyPtr key = NewP256Key();
    if (!key) {
        return false;
    }
    X509Ptr cert = MakeCertificate(Role::Client, CN_PREFIX + label, key.get(), &issuer);
    if (!cert || !WritePem(keyPath, key.get(), NULL) || !WritePem(crtPath, NULL, cert.get()) ||
        !WritePem(issuerPath, NULL, issuer.cert.get())) {
        return false;
    }
    // For Windows tools such as YABE (issue #38).
    const fs::path pfxPath = dir / (label + CLIENT_PFX_EXTENSION);
    const fs::path derPath = dir / ISSUER_CERTIFICATE_DER_FILE;
    if (!WritePfx(pfxPath, key.get(), cert.get(), issuer.cert.get(), CN_PREFIX + label) ||
        !WriteDer(derPath, issuer.cert.get()) ||
        !WriteText(dir / YABE_CONFIG_FILE, YabeConfig(hubUri, pfxPath, derPath))) {
        return false;
    }
    if (!WriteText(dir / BACNETSC_CONFIG_FILE, BacnetScConfig(hubUri)) ||
        !WriteText(dir / README_FILE,
                   ReplaceAll(ReplaceAll(CLIENT_DIR_README, "%LABEL%", label), "%HUBURI%", hubUri))) {
        return false;
    }
    RecordInManifest(certDir, label, "client", std::string(CLIENTS_DIR) + "/" + label + "/", cert.get());
    return true;
}

// Highest NN among clients/<label>-NN folders (0 if none).
unsigned HighestClientNumber(const fs::path& certDir, const std::string& label) {
    // Escape the label so a prefix like "ahu.1" is matched literally.
    const std::string escaped = std::regex_replace(label, std::regex(R"([.^$|()\[\]{}*+?\\])"), R"(\$&)");
    const std::regex pattern("^" + escaped + "-([0-9]+)$");
    unsigned highest = 0;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(certDir / CLIENTS_DIR, ec)) {
        std::smatch m;
        const std::string name = entry.path().filename().string();
        if (entry.is_directory() && std::regex_match(name, m, pattern)) {
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
    if (label.empty() || label == HUB_LABEL || label == ISSUER_LABEL ||
        !std::regex_match(label, std::regex("[A-Za-z0-9_.-]+"))) {
        fprintf(stderr, "Error: --cert-label \"%s\" must be letters, digits, '-', '_' or '.', and not "
                        "\"%s\" or \"%s\".\n", label.c_str(), HUB_LABEL, ISSUER_LABEL);
        return false;
    }
    return true;
}

bool IssueClients(const fs::path& certDir, const Credential& issuer, unsigned count, const std::string& label,
                  const std::string& hubUri) {
    const unsigned first = HighestClientNumber(certDir, label) + 1;
    for (unsigned n = first; n < first + count; ++n) {
        if (!IssueClient(certDir, issuer, ClientLabel(label, n), hubUri)) {
            return false;
        }
    }
    return true;
}

}  // namespace

std::string ResolveCertFile(const std::string& certDir, const char* name, const char* legacyName) {
    const fs::path dir(certDir);
    if (fs::exists(dir / name) || !fs::exists(dir / legacyName)) {
        return name;
    }
    return legacyName;
}

bool GenerateCertificateSet(const std::string& certDirArg, unsigned clientCount,
                            const std::string& clientLabel, const std::string& hubUri, bool force) {
    if (!ValidLabel(clientLabel)) {
        return false;
    }
    const fs::path certDir(certDirArg);
    std::error_code ec;
    fs::create_directories(certDir, ec);

    // Every file a certificate set owns, in both namings.
    const char* const setFiles[] = {
        ISSUER_CERTIFICATE_FILE, ISSUER_PRIVATE_KEY_FILE, OPERATIONAL_CERTIFICATE_FILE,
        PRIVATE_KEY_FILE, CERTIFICATE_SIGNING_REQUEST_FILE,
        LEGACY_ISSUER_CERTIFICATE_FILE, LEGACY_ISSUER_PRIVATE_KEY_FILE,
        LEGACY_OPERATIONAL_CERTIFICATE_FILE, LEGACY_PRIVATE_KEY_FILE,
        LEGACY_CERTIFICATE_SIGNING_REQUEST_FILE, ISSUER_CERTIFICATE_2_FILE, TRUSTED_ISSUERS_FILE,
        "ca.srl", "node.crt", "node.key", MANIFEST_FILE, README_FILE};
    if (!force) {
        for (const char* name : setFiles) {
            if (fs::exists(certDir / name) && strcmp(name, MANIFEST_FILE) != 0 && strcmp(name, README_FILE) != 0 &&
                strcmp(name, TRUSTED_ISSUERS_FILE) != 0) {
                fprintf(stderr,
                        "Error: \"%s\" already exists. Replacing the issuer invalidates every certificate "
                        "already handed out. Use --add-client-certs to add clients to the existing set, "
                        "or add --force to start over.\n",
                        (certDir / name).string().c_str());
                return false;
            }
        }
    } else {
        // Start over: remove the old set, every client folder and the
        // manifest, so nothing signed by the old issuer is left behind.
        for (const char* name : setFiles) {
            fs::remove(certDir / name, ec);
        }
        fs::remove_all(certDir / CLIENTS_DIR, ec);
    }

    printf("Generating lab BACnet/SC certificates in \"%s\" (LAB TESTING ONLY):\n", certDir.string().c_str());
    Credential issuer;
    issuer.key = NewP256Key();
    if (!issuer.key) {
        return false;
    }
    // A short random suffix gives every lab issuer its own subject name, so two
    // certificate sets (e.g. an "add issuer" test) never have issuers that can
    // only be told apart by key identifier.
    unsigned char suffix[4];
    RAND_bytes(suffix, sizeof(suffix));
    char suffixHex[9];
    snprintf(suffixHex, sizeof(suffixHex), "%02X%02X%02X%02X", suffix[0], suffix[1], suffix[2], suffix[3]);
    issuer.cert = MakeCertificate(Role::Ca, std::string(CA_COMMON_NAME) + " " + suffixHex, issuer.key.get(), NULL);
    if (!issuer.cert || !WritePem(certDir / ISSUER_PRIVATE_KEY_FILE, issuer.key.get(), NULL) ||
        !WritePem(certDir / ISSUER_CERTIFICATE_FILE, NULL, issuer.cert.get())) {
        return false;
    }
    RecordInManifest(certDir, ISSUER_LABEL, "issuer", "", issuer.cert.get());

    if (!IssueHub(certDir, issuer, hubUri) || !IssueClients(certDir, issuer, clientCount, clientLabel, hubUri) ||
        !WriteText(certDir / README_FILE, CERT_DIR_README)) {
        return false;
    }
    printf("Wrote %s: what each file is, which are private, and how to use them.\n", README_FILE);
    printf("Client bacnetsc.config files point at %s (change with --cert-hub-uri).\n", hubUri.c_str());
    printf("Done. Give each connecting device its own %s/<label>/ folder.\n"
           "Keep %s private: it is only needed to sign more clients (--add-client-certs).\n",
           CLIENTS_DIR, ISSUER_PRIVATE_KEY_FILE);
    return true;
}

bool AddClientCertificates(const std::string& certDirArg, unsigned clientCount,
                           const std::string& clientLabel, const std::string& hubUri) {
    if (!ValidLabel(clientLabel)) {
        return false;
    }
    const fs::path certDir(certDirArg);
    Credential issuer;
    if (!LoadIssuer(certDir, &issuer)) {
        return false;
    }
    printf("Adding %u client certificate(s) signed by the existing issuer in \"%s\":\n", clientCount,
           certDir.string().c_str());
    if (!IssueClients(certDir, issuer, clientCount, clientLabel, hubUri) ||
        !WriteText(certDir / README_FILE, CERT_DIR_README)) {
        return false;
    }
    printf("Done. The running hub already trusts these (same issuer) - no restart needed.\n");
    return true;
}

}  // namespace CertTool
