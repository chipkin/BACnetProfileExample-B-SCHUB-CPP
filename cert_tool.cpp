// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// cert_tool.cpp - see cert_tool.h for what this does and why.

#include "cert_tool.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
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

PkeyPtr NewP256Key() {
    PkeyPtr key(EVP_EC_gen("P-256"));
    if (!key) {
        PrintOpenSslError("could not generate an ECDSA P-256 key");
    }
    return key;
}

std::string LocalHostname() {
    char name[256] = {0};
    if (gethostname(name, sizeof(name) - 1) != 0 || name[0] == '\0') {
        return "localhost";
    }
    return name;
}

// The subjectAltName the hub asks for: localhost, 127.0.0.1, this computer's
// host name, and the host devices dial (from the hub URI), so a device that
// checks host names accepts wss://<that host>/. The CA decides whether to
// copy it into the certificate.
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

// A certificate, PEM or DER.
X509Ptr CertFromBytes(const std::string& bytes) {
    BIO* bio = BIO_new_mem_buf(bytes.data(), (int)bytes.size());
    X509Ptr cert(PEM_read_bio_X509(bio, NULL, NULL, NULL));
    BIO_free(bio);
    if (!cert) {
        ERR_clear_error();
        const unsigned char* p = (const unsigned char*)bytes.data();
        cert.reset(d2i_X509(NULL, &p, (long)bytes.size()));
    }
    ERR_clear_error();
    return cert;
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

// The hub's CSR: CN=<subjectCn>, and requested extensions: TLS server and
// client use (a BACnet/SC certificate is presented at both ends of a
// connection) and the host names devices dial.
ReqPtr MakeHubCsr(EVP_PKEY* key, const std::string& subjectCn, const std::string& subjectAltName) {
    ReqPtr req(X509_REQ_new());
    if (!req || X509_REQ_set_version(req.get(), 0) != 1) {
        PrintOpenSslError("could not make the certificate signing request");
        return nullptr;
    }
    X509_NAME* name = X509_REQ_get_subject_name(req.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, (const unsigned char*)subjectCn.c_str(), -1, -1, 0);
    X509_REQ_set_pubkey(req.get(), key);

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, NULL, NULL, req.get(), NULL, 0);
    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
    X509_EXTENSION* san = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, subjectAltName.c_str());
    X509_EXTENSION* eku = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, "serverAuth,clientAuth");
    bool ok = san != NULL && eku != NULL;
    if (san != NULL) {
        sk_X509_EXTENSION_push(exts, san);
    }
    if (eku != NULL) {
        sk_X509_EXTENSION_push(exts, eku);
    }
    ok = ok && X509_REQ_add_extensions(req.get(), exts) == 1;
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    ok = ok && X509_REQ_sign(req.get(), key, EVP_sha256()) > 0;
    if (!ok) {
        PrintOpenSslError("could not make the certificate signing request");
        return nullptr;
    }
    return req;
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

// --- certificate facts ---------------------------------------------------------

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

// A name as one line of text, e.g. "CN=AHU 7,O=Example Corp".
std::string NameText(const X509_NAME* name) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return "?";
    }
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB);
    return BioText(bio);
}

// The file name part of a '/'-separated zip path.
std::string BaseName(const std::string& path) {
    const size_t slash = path.rfind('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

bool StartsWith(const std::string& text, const std::string& prefix) {
    return text.compare(0, prefix.size(), prefix) == 0;
}

const char* const REQUEST_NOTES = R"(Certificate request for a BACnet/SC hub (CAS BACnet Stack B-SCHUB example).

Sign cert1/device-%INSTANCE%/port-2/csr-hub.pem. This port is a BACnet/SC hub
(see the hub/ folder): its certificate needs extendedKeyUsage serverAuth and
clientAuth. The request also lists the subjectAltName the hub wants.

Return a CARI response: this tree plus opr-hub.pem next to the CSR and your
issuer certificate(s) in cert1/issuer/. Then install it on the hub with
--import-cari.
)";

}  // namespace

// =============================================================================
// Building blocks
// =============================================================================

bool HubRequestZip(const CertLayout::HubCertPaths& paths, std::string* zipBytes, std::string* error) {
    if (!fs::exists(paths.certificateSigningRequest)) {
        *error = "the hub has no certificate signing request yet - start the hub once to make one";
        return false;
    }
    const std::string csr = ReadFile(paths.certificateSigningRequest);
    if (!ReqFromBytes(csr)) {
        *error = "\"" + paths.certificateSigningRequest + "\" is not a certificate signing request";
        return false;
    }
    Cari::Tree request;
    request.AddFile(paths.portFolder + "/" + fs::path(paths.certificateSigningRequest).filename().string(), csr);
    request.AddFolder(paths.portFolder + "/hub");
    std::string notes = REQUEST_NOTES;
    const std::string token = "%INSTANCE%";
    notes.replace(notes.find(token), token.size(), std::to_string(paths.folderDeviceInstance));
    request.AddFile("cert1/request-notes.txt", notes);
    *zipBytes = Cari::WriteZip(request);
    return true;
}

bool ReadCariResponse(const CertLayout::HubCertPaths& paths, const std::string& zipBytes, ResponseFiles* out,
                      std::string* error) {
    Cari::Tree tree;
    if (!Cari::ReadZip(zipBytes, &tree, error)) {
        return false;
    }
    if (!fs::exists(paths.certificateSigningRequest)) {
        *error = "the hub has no certificate signing request to match the response against - start the "
                 "hub once first (it makes its key and request)";
        return false;
    }
    ReqPtr csr = ReqFromBytes(ReadFile(paths.certificateSigningRequest));
    EVP_PKEY* csrKey = csr ? X509_REQ_get0_pubkey(csr.get()) : NULL;
    if (csrKey == NULL) {
        *error = "could not read the hub's certificate signing request \"" + paths.certificateSigningRequest + "\"";
        return false;
    }

    // The hub's certificate: the opr- file whose public key is the hub's.
    // Its own port folder first, then anywhere in the zip.
    std::vector<std::string> candidates;
    const std::string own = paths.portFolder.empty() ? std::string() : paths.portFolder + "/opr-hub.pem";
    if (!own.empty() && tree.Has(own)) {
        candidates.push_back(own);
    }
    for (const auto& kv : tree.files) {
        if (StartsWith(BaseName(kv.first), "opr-") && kv.first != own) {
            candidates.push_back(kv.first);
        }
    }
    if (candidates.empty()) {
        *error = "the zip has no certificate (no opr-*.pem) - is it a CARI response, not the request?";
        return false;
    }
    X509Ptr operational;
    for (const std::string& path : candidates) {
        X509Ptr cert = CertFromBytes(tree.files[path]);
        if (cert && EVP_PKEY_eq(X509_get0_pubkey(cert.get()), csrKey) == 1) {
            operational = std::move(cert);
            out->source = path;
            break;
        }
    }
    if (!operational) {
        *error = "none of the " + std::to_string(candidates.size()) +
                 " certificate(s) in the zip is for this hub's key - the response is for another request";
        return false;
    }
    if (X509_cmp_current_time(X509_get0_notAfter(operational.get())) < 0) {
        *error = "the hub's certificate in the zip expired on " + NotAfter(operational.get());
        return false;
    }

    // The issuers: cert1/issuer/iss-*, the one that signed the hub's
    // certificate first (File 3), then one more (File 4).
    std::vector<X509Ptr> issuers;
    for (const auto& kv : tree.files) {
        if (StartsWith(kv.first, "cert1/issuer/") && StartsWith(BaseName(kv.first), "iss-")) {
            X509Ptr cert = CertFromBytes(kv.second);
            if (!cert) {
                *error = "\"" + kv.first + "\" in the zip is not a certificate";
                return false;
            }
            issuers.push_back(std::move(cert));
        }
    }
    if (issuers.empty()) {
        *error = "the zip has no issuer certificate (cert1/issuer/iss-*.pem)";
        return false;
    }
    auto signer = std::find_if(issuers.begin(), issuers.end(), [&](const X509Ptr& issuer) {
        return X509_check_issued(issuer.get(), operational.get()) == X509_V_OK &&
               X509_verify(operational.get(), X509_get0_pubkey(issuer.get())) == 1;
    });
    if (signer == issuers.end()) {
        ERR_clear_error();
        *error = "no issuer certificate in the zip signed the hub's certificate (issued by \"" +
                 NameText(X509_get_issuer_name(operational.get())) + "\")";
        return false;
    }
    std::rotate(issuers.begin(), signer, signer + 1);
    if (issuers.size() > 2) {
        *error = "the zip has " + std::to_string(issuers.size()) +
                 " issuer certificates; the hub holds at most 2 (Issuer_Certificate_Files)";
        return false;
    }

    out->operationalCertificate = CertPem(operational.get());
    out->issuers.clear();
    for (const X509Ptr& issuer : issuers) {
        out->issuers.push_back(CertPem(issuer.get()));
    }
    out->subject = NameText(X509_get_subject_name(operational.get()));
    out->issuerSubject = NameText(X509_get_issuer_name(operational.get()));
    out->notAfter = NotAfter(operational.get());
    out->fingerprint = Sha256Fingerprint(operational.get());
    return true;
}

// =============================================================================
// Command-line modes
// =============================================================================

RequestResult EnsureHubRequest(const std::string& certDir, uint32_t hubDeviceInstance, const std::string& subjectCn,
                               const std::string& hubUri, std::string* message) {
    const CertLayout::HubCertPaths paths = CertLayout::ResolveHubCertPaths(certDir, hubDeviceInstance);
    const fs::path zipPath = fs::absolute(fs::path(certDir) / HUB_REQUEST_ZIP);

    // Already there: never overwrite it - it may be the very file that was
    // sent to the CA. Delete it to have it made again.
    if (fs::exists(zipPath)) {
        *message = "\"" + zipPath.string() + "\" already exists (delete it to make a new one)";
        return RequestResult::AlreadyExists;
    }

    // THE PRIVATE KEY IS NEVER REPLACED. A new key is made only when the hub
    // has none at all - no key-hub.pem and no pending key from
    // GENERATE_CSR_FILE - so a key the running certificates use is never
    // touched. With a key, the request is made from the CSR already on disk.
    const bool haveKey = fs::exists(paths.privateKey);
    const bool havePendingKey = !paths.pendingPrivateKey.empty() && fs::exists(paths.pendingPrivateKey);
    std::string newKeyNote;
    if (!fs::exists(paths.certificateSigningRequest)) {
        if (haveKey || havePendingKey) {
            *message = "not made: \"" + (haveKey ? paths.privateKey : paths.pendingPrivateKey) +
                       "\" has no certificate signing request (csr-hub.pem) next to it, and the key is never "
                       "replaced. Move the key away (or put its CSR back) and restart to make one.";
            return RequestResult::Failed;
        }
        PkeyPtr key = NewP256Key();
        if (!key) {
            *message = "not made: could not generate a private key";
            return RequestResult::Failed;
        }
        ReqPtr csr = MakeHubCsr(key.get(), subjectCn, HubSubjectAltName(hubUri));
        if (!csr) {
            *message = "not made: could not make the certificate signing request";
            return RequestResult::Failed;
        }
        std::error_code ec;
        fs::create_directories(fs::path(paths.certDir) / paths.portFolder / "hub", ec);
        if (!WriteFile(paths.privateKey, KeyPem(key.get()), true) ||
            !WriteFile(paths.certificateSigningRequest, ReqPem(csr.get()))) {
            *message = "not made: could not write the new key and request in \"" + certDir + "\"";
            return RequestResult::Failed;
        }
        newKeyNote = " with a new private key (" + CertLayout::RelativeTo(certDir, paths.privateKey) +
                     ", keep it private)";
    }

    std::string zip;
    std::string error;
    if (!HubRequestZip(paths, &zip, &error)) {
        *message = "not made: " + error;
        return RequestResult::Failed;
    }
    if (!WriteFile(zipPath, zip)) {
        *message = "not made: could not write \"" + zipPath.string() + "\"";
        return RequestResult::Failed;
    }
    *message = "created \"" + zipPath.string() + "\"" + newKeyNote +
               " - send it to your Certificate Authority, then install its response with --import-cari";
    return RequestResult::Created;
}

bool ImportCariResponse(const std::string& certDir, uint32_t hubDeviceInstance, const std::string& zipPath) {
    const CertLayout::HubCertPaths paths = CertLayout::ResolveHubCertPaths(certDir, hubDeviceInstance);
    std::ifstream in(zipPath, std::ios::binary);
    if (!in) {
        fprintf(stderr, "Error: could not read \"%s\".\n", zipPath.c_str());
        return false;
    }
    const std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    ResponseFiles files;
    std::string error;
    if (!ReadCariResponse(paths, bytes, &files, &error)) {
        fprintf(stderr, "Error: %s: %s\n", zipPath.c_str(), error.c_str());
        return false;
    }
    if (!WriteFile(paths.operationalCertificate, files.operationalCertificate) ||
        !WriteFile(paths.issuerCertificate1, files.issuers[0])) {
        return false;
    }
    // One issuer fills both issuer slots, so a stale second issuer is not left
    // trusted.
    if (!WriteFile(paths.issuerCertificate2, files.issuers.size() > 1 ? files.issuers[1] : files.issuers[0])) {
        return false;
    }
    printf("Installed the hub's certificate from %s (%s):\n", zipPath.c_str(), files.source.c_str());
    printf("  subject      %s\n  issued by    %s\n  expires      %s\n  SHA-256      %s\n", files.subject.c_str(),
           files.issuerSubject.c_str(), files.notAfter.c_str(), files.fingerprint.c_str());
    printf("  %s\n  %s\n  %s\n", CertLayout::RelativeTo(certDir, paths.operationalCertificate).c_str(),
           CertLayout::RelativeTo(certDir, paths.issuerCertificate1).c_str(),
           CertLayout::RelativeTo(certDir, paths.issuerCertificate2).c_str());
    printf("Restart the hub to use it.\n");
    return true;
}

}  // namespace CertTool
