// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// cert_portal.cpp - see cert_portal.h.

#include "cert_portal.h"

#include <openssl/evp.h>

#include <time.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>

#include "CASExampleLog.h"
#include "cari.h"
#include "cert_inspect.h"
#include "cert_portal_page.h"
#include "cert_tool.h"
#include "json_writer.h"
#include "sc_transport/LogSafe.h"
#include "sc_transport/ScDiagnostics.h"

namespace fs = std::filesystem;

namespace CertPortal {
namespace {

Config g_config;

// Wrong passwords: at most kFailuresPerAddress a minute from one address and
// kFailuresTotal from everyone together (the /certs upload limits, issue #24).
const unsigned kFailuresPerAddress = 5;
const unsigned kFailuresTotal = 30;
std::map<std::string, std::deque<std::chrono::steady_clock::time_point>> g_failuresByAddress;
std::deque<std::chrono::steady_clock::time_point> g_failuresTotal;
std::mutex g_failureMutex;

const char* const CARI_RESPONSES_DIR = "cari-responses";

void Prune(std::deque<std::chrono::steady_clock::time_point>* q) {
    const auto cutoff = std::chrono::steady_clock::now() - std::chrono::minutes(1);
    while (!q->empty() && q->front() < cutoff) {
        q->pop_front();
    }
}

bool TooManyFailures(const std::string& address) {
    std::lock_guard<std::mutex> lock(g_failureMutex);
    Prune(&g_failuresTotal);
    auto& mine = g_failuresByAddress[address];
    Prune(&mine);
    return mine.size() >= kFailuresPerAddress || g_failuresTotal.size() >= kFailuresTotal;
}

void RecordFailure(const std::string& address) {
    std::lock_guard<std::mutex> lock(g_failureMutex);
    const auto now = std::chrono::steady_clock::now();
    g_failuresByAddress[address].push_back(now);
    g_failuresTotal.push_back(now);
    if (g_failuresByAddress.size() > 256) {  // bounded, like the upload buckets
        g_failuresByAddress.erase(g_failuresByAddress.begin());
    }
}

std::string Base64Decode(const std::string& in) {
    if (in.empty() || in.size() % 4 != 0 || in.size() > 4096) {
        return std::string();
    }
    std::string out(in.size() / 4 * 3, '\0');
    const int n = EVP_DecodeBlock((unsigned char*)&out[0], (const unsigned char*)in.data(), (int)in.size());
    if (n < 0) {
        return std::string();
    }
    size_t len = (size_t)n;
    for (size_t i = in.size(); i > 0 && in[i - 1] == '='; --i) {
        --len;
    }
    out.resize(len);
    return out;
}

std::string ReadFile(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    std::stringstream s;
    s << f.rdbuf();
    return s.str();
}

void Json(CASSc::HttpResponse* r, int status, const std::string& json) {
    r->status = status;
    r->contentType = "application/json";
    r->body = json;
    r->headers.push_back({"cache-control", "no-store"});
}

void Error(CASSc::HttpResponse* r, int status, const std::string& error, const std::string& fix,
           const std::string& detail = std::string()) {
    Json(r, status, Json::Object()
                        .Add("ok", Json::Bool(false))
                        .Add("error", Json::Str(error))
                        .Add("fix", Json::Str(fix))
                        .Add("detail", Json::Str(detail))
                        .Text());
}

void Audit(const CASSc::HttpRequest& request, const std::string& what) {
    CASExampleHelper::Log(CASExampleHelper::LogLevel::Info, "setup guide: %s (from %s%s)", what.c_str(),
                          request.peerAddress.c_str(), request.tls ? ", HTTPS" : "");
}

// --- the gate ---------------------------------------------------------------------

struct Gate {
    bool passwordProtectedKey = false;
    bool allowedWithoutPassword = false;  // no password, and on loopback
    std::string explanation;
};

Gate DescribeGate(const CASSc::HttpRequest& request) {
    Gate gate;
    const char* password = g_config.keyPassword ? g_config.keyPassword() : nullptr;
    gate.passwordProtectedKey = password != nullptr && password[0] != '\0';
    if (gate.passwordProtectedKey) {
        gate.explanation = "Signing and making keys need the password of the hub's private key (sc-key-password, or "
                           "the one typed when the hub started).";
        if (!request.tls && !request.peerIsLoopback) {
            gate.explanation += " This page is plain HTTP from another computer, so the password would cross the "
                                "network in clear: the hub refuses it. Use the page on the hub's own computer, or "
                                "start the hub with --http-tls.";
        }
    } else if (request.peerIsLoopback) {
        gate.allowedWithoutPassword = true;
        gate.explanation = "The hub's private key has no password, so signing works only from the hub's own "
                           "computer - which this is.";
    } else {
        gate.explanation = "The hub's private key has no password, so signing works only from the hub's own computer "
                           "(127.0.0.1). Open this page there, or protect the key with a password (see the manual, "
                           "\"Password-protected private keys\"), set sc-key-password and restart the hub.";
    }
    return gate;
}

// True if the Host header names this computer's loopback (127.x, localhost,
// [::1]), with or without a port.
bool HostIsLoopback(const std::string& hostHeader) {
    std::string host = hostHeader;
    if (!host.empty() && host[0] == '[') {
        host = host.substr(1, host.find(']') == std::string::npos ? std::string::npos : host.find(']') - 1);
    } else {
        host = host.substr(0, host.find(':'));
    }
    for (char& c : host) {
        c = (char)tolower((unsigned char)c);
    }
    return host == "localhost" || host == "::1" || host.compare(0, 4, "127.") == 0;
}

// True if the request may do something privileged; otherwise fills *response.
//
// Two defences on top of the password, for the browser on the hub's own
// computer (where, with no key password, loopback is trusted):
//  - every privileged call must carry "Authorization: HubKey ..." (the page
//    always sends it, "HubKey -" when there is no password). Another web
//    site's page can't add that header to a request to this hub without a
//    CORS preflight, which the hub never answers, so it can't make the hub
//    sign or generate anything (cross-site request forgery).
//  - with no password, the Host header must be a loopback name too, so a
//    DNS-rebinding page (attacker.example resolving to 127.0.0.1, which would
//    make its requests "same-origin") is refused.
bool Authorize(const CASSc::HttpRequest& request, CASSc::HttpResponse* response, const std::string& action) {
    const Gate gate = DescribeGate(request);
    static const char kScheme[] = "HubKey";
    if (request.authorization.compare(0, sizeof(kScheme) - 1, kScheme) != 0) {
        Audit(request, "REFUSED " + action + " - no Authorization: HubKey header (not from the set-up guide)");
        Error(response, 403, "this request didn't come from the set-up guide",
              "Use the page at /setup, or send \"Authorization: HubKey <base64 of the hub key's password>\" "
              "(\"HubKey -\" when the key has no password).");
        return false;
    }
    if (!gate.passwordProtectedKey) {
        if (gate.allowedWithoutPassword && HostIsLoopback(request.host)) {
            return true;
        }
        if (gate.allowedWithoutPassword) {
            Audit(request, "REFUSED " + action + " - Host \"" + CASSc::SafeForLog(request.host) +
                               "\" is not a loopback name (DNS rebinding?)");
            Error(response, 403, "open this page as http://127.0.0.1 (or localhost)",
                  "Without a key password, signing is only allowed to a page loaded from 127.0.0.1 or localhost.");
            return false;
        }
        Audit(request, "REFUSED " + action + " - no key password and not on loopback");
        Error(response, 403, "not allowed from this computer", gate.explanation);
        return false;
    }
    if (!request.tls && !request.peerIsLoopback) {
        Audit(request, "REFUSED " + action + " - password over plain HTTP from another computer");
        Error(response, 403, "the password can't be sent over plain HTTP from another computer", gate.explanation);
        return false;
    }
    if (TooManyFailures(request.peerAddress)) {
        Audit(request, "REFUSED " + action + " - too many wrong passwords");
        Error(response, 429, "too many wrong passwords - wait a minute",
              "At most 5 wrong passwords a minute are accepted from one address (30 in total).");
        return false;
    }
    std::string presented;
    if (request.authorization.size() > sizeof(kScheme)) {  // "HubKey " + the base64
        presented = Base64Decode(request.authorization.substr(sizeof(kScheme)));
    }
    if (presented.empty() || !CASSc::SecretsEqual(presented, g_config.keyPassword())) {
        if (!presented.empty()) {
            RecordFailure(request.peerAddress);  // a wrong guess; a request with no password isn't one
        }
        Audit(request, "REFUSED " + action + std::string(" - ") + (presented.empty() ? "no password" : "wrong password"));
        Error(response, 401, presented.empty() ? "the hub key's password is needed" : "wrong password",
              "Enter the password of the hub's private key (the config file's sc-key-password, or the one typed "
              "when the hub started).");
        return false;
    }
    return true;
}

// --- downloads ----------------------------------------------------------------------

// A path inside a folder: relative, '/'-separated, no "..", no backslash.
bool SafeRelative(const std::string& p) {
    if (p.empty() || p[0] == '/' || p.find('\\') != std::string::npos || p.find(':') != std::string::npos) {
        return false;
    }
    std::stringstream in(p);
    std::string part;
    while (std::getline(in, part, '/')) {
        if (part.empty() || part == "." || part == "..") {
            return false;
        }
    }
    return true;
}

// A key file, a .pfx, or a zip carrying a key.
bool IsPrivateFile(const fs::path& path) {
    const std::string name = path.filename().string();
    if (name.compare(0, 4, "key-") == 0 || path.extension() == ".pfx") {
        return true;
    }
    if (path.extension() == ".zip") {
        Cari::Tree tree;
        std::string error;
        if (Cari::ReadZip(ReadFile(path), &tree, &error)) {
            for (const auto& f : tree.files) {
                if (fs::path(f.first).filename().string().compare(0, 4, "key-") == 0) {
                    return true;
                }
            }
        }
    }
    return false;
}

std::string Describe(const std::string& rel) {
    const std::string name = fs::path(rel).filename().string();
    if (name.compare(0, 4, "opr-") == 0) return "the device's certificate -> its Operational_Certificate_File";
    if (name.compare(0, 4, "key-") == 0) return "the device's private key - keep it secret";
    if (name.compare(0, 4, "csr-") == 0) return "the request it was signed from";
    if (name == "iss-1.pem" || name == "iss-2.pem") return "the issuer -> the device's Issuer_Certificate_Files";
    if (name == "iss-1.cer") return "the issuer in DER, for Windows tools";
    if (name.size() > 4 && name.compare(name.size() - 4, 4, ".zip") == 0) return "the device's CARI response: the cert1/ files below, zipped";
    if (name == "bacnetsc.config") return "import into the CAS BACnet Explorer";
    if (name == "yabe-bacnetsc.config") return "YABE's BACnet/SC channel file";
    if (name.size() > 4 && name.compare(name.size() - 4, 4, ".pfx") == 0) return "certificate + key for YABE/Windows (empty password) - keep it secret";
    if (name == "readme.txt") return "what each file is";
    if (name == "response-notes.txt") return "the CA's note";
    if (name == "errors.txt") return "why requests were refused";
    return "";
}

std::string FolderDownloads(const std::string& label) {
    const fs::path dir = fs::path(g_config.certPaths().clientsDir) / label;
    Json::Array arr;
    std::error_code ec;
    std::vector<std::string> rels;
    for (auto it = fs::recursive_directory_iterator(dir, ec); !ec && it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        if (it->is_regular_file()) {
            rels.push_back(fs::relative(it->path(), dir, ec).generic_string());
        }
    }
    std::sort(rels.begin(), rels.end(), [](const std::string& a, const std::string& b) {
        // the zip first, then cert1/..., then the tool files
        const bool az = a.find(".zip") != std::string::npos, bz = b.find(".zip") != std::string::npos;
        if (az != bz) return az;
        return a < b;
    });
    for (const std::string& rel : rels) {
        arr.Add(Json::Object()
                    .Add("name", Json::Str(rel))
                    .Add("url", Json::Str("/api/download/" + label + "/" + rel))
                    .Add("private", Json::Bool(IsPrivateFile(dir / rel)))
                    .Add("bytes", Json::Num((int64_t)fs::file_size(dir / rel, ec)))
                    .Add("description", Json::Str(Describe(rel)))
                    .Text());
    }
    return arr.Text();
}

std::string ItemsJson(const std::vector<CertTool::SignedItem>& items) {
    Json::Array arr;
    for (const CertTool::SignedItem& i : items) {
        arr.Add(Json::Object()
                    .Add("where", Json::Str(i.where))
                    .Add("signed", Json::Bool(i.signedOk))
                    .Add("error", Json::Str(i.error))
                    .Add("subject", Json::Str(i.subject))
                    .Add("serial", Json::Str(i.serial))
                    .Add("expires", Json::Str(i.notAfter))
                    .Add("fingerprint", Json::Str(i.fingerprint))
                    .Add("hubPort", Json::Bool(i.isHubPort))
                    .Text());
    }
    return arr.Text();
}

std::string Arg(const CASSc::HttpRequest& r, const char* name) {
    const auto it = r.query.find(name);
    return it == r.query.end() ? std::string() : it->second;
}

// The device folder options from ?label=&instance=&port= .
bool ClientOptionsFrom(const CASSc::HttpRequest& request, CertTool::ClientOptions* client, CASSc::HttpResponse* response) {
    client->label = Arg(request, "label");
    if (!client->label.empty() && !CertTool::IsValidLabel(client->label)) {
        Error(response, 400, "the device name \"" + client->label + "\" can't be a folder name",
              "Use letters, digits, '-', '_' and '.', e.g. ahu-7.");
        return false;
    }
    const std::string instance = Arg(request, "instance");
    if (!instance.empty()) {
        char* end = nullptr;
        const unsigned long n = std::strtoul(instance.c_str(), &end, 10);
        if (end == instance.c_str() || *end != '\0' || n > 4194302UL) {
            Error(response, 400, "the device instance must be a number from 0 to 4194302",
                  "It is the device's BACnet Device object instance.");
            return false;
        }
        client->deviceInstance = (int64_t)n;
    }
    const std::string port = Arg(request, "port");
    if (!port.empty()) {
        if (!Cari::IsValidName(port)) {
            Error(response, 400, "the port id can't contain < > : \" / \\ | ? *", "Use e.g. 1, or sc.");
            return false;
        }
        client->portId = port;
    }
    const std::vector<std::string> uris = g_config.hubUris();
    client->hubUri = uris.empty() ? std::string() : uris.front();
    return true;
}

std::string TimestampForFile() {
    const time_t now = time(nullptr);
    struct tm t;
#if defined(_WIN32)
    gmtime_s(&t, &now);
#else
    gmtime_r(&now, &t);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%Y%m%d-%H%M%S", &t);
    return buf;
}

// --- routes -----------------------------------------------------------------------------

void Info(const CASSc::HttpRequest& request, CASSc::HttpResponse* response) {
    const CertLayout::HubCertPaths paths = g_config.certPaths();
    const Gate gate = DescribeGate(request);
    std::string caError;
    const bool canSign = CertTool::CheckSigningCa(paths, &caError);
    Json::Array uris;
    for (const std::string& u : g_config.hubUris()) {
        uris.Add(Json::Str(u));
    }
    Json::Array issuers;
    issuers.Add(Json::Object()
                    .Add("slot", Json::Num(1))
                    .Add("path", Json::Str(CertLayout::RelativeTo(paths.certDir, paths.issuerCertificate1)))
                    .Add("items", CertInspect::CertificateFileJson(paths.issuerCertificate1, "Issuer slot 1 (iss-1.pem)",
                                                                   false, paths))
                    .Text());
    std::error_code ec;
    if (fs::exists(paths.issuerCertificate2, ec)) {
        issuers.Add(Json::Object()
                        .Add("slot", Json::Num(2))
                        .Add("path", Json::Str(CertLayout::RelativeTo(paths.certDir, paths.issuerCertificate2)))
                        .Add("items", CertInspect::CertificateFileJson(paths.issuerCertificate2,
                                                                       "Issuer slot 2 (iss-2.pem)", false, paths))
                        .Text());
    }
    Json(response, 200,
         Json::Object()
             .Add("app", Json::Str(g_config.appName))
             .Add("version", Json::Str(g_config.appVersion))
             .Add("stack", Json::Str(g_config.stackVersion))
             .Add("deviceName", Json::Str(g_config.deviceName))
             .Add("deviceInstance", Json::Num(g_config.deviceInstance))
             .Add("scPort", Json::Num(g_config.scPort))
             .Add("hubUris", uris.Text())
             .Add("certDir", Json::Str(paths.certDir))
             .Add("layout", Json::Str(paths.KindName()))
             .Add("hubPortFolder", Json::Str(paths.portFolder))
             .Add("gate", Json::Object()
                              .Add("passwordProtectedKey", Json::Bool(gate.passwordProtectedKey))
                              .Add("allowedWithoutPassword", Json::Bool(gate.allowedWithoutPassword))
                              .Add("youAreLoopback", Json::Bool(request.peerIsLoopback))
                              .Add("tls", Json::Bool(request.tls))
                              .Add("explanation", Json::Str(gate.explanation))
                              .Text())
             .Add("canSign", Json::Bool(canSign))
             .Add("signingProblem", Json::Str(caError))
             .Add("hubCertificate",
                  Json::Object()
                      .Add("path", Json::Str(CertLayout::RelativeTo(paths.certDir, paths.operationalCertificate)))
                      .Add("items", CertInspect::CertificateFileJson(paths.operationalCertificate,
                                                                     "Hub certificate (opr-hub.pem)", true, paths))
                      .Text())
             .Add("issuers", issuers.Text())
             .Text());
}

void IssuerFile(const std::string& name, CASSc::HttpResponse* response) {
    const CertLayout::HubCertPaths paths = g_config.certPaths();
    std::string bytes;
    if (name == "iss-1.pem") {
        bytes = ReadFile(paths.issuerCertificate1);
    } else if (name == "iss-2.pem") {
        bytes = ReadFile(paths.issuerCertificate2);
    } else if (name == "iss-1.cer") {
        // DER of the first certificate in iss-1.pem.
        const std::string pem = ReadFile(paths.issuerCertificate1);
        const size_t b = pem.find("-----BEGIN CERTIFICATE-----");
        const size_t e = pem.find("-----END CERTIFICATE-----");
        if (b != std::string::npos && e != std::string::npos) {
            std::string body;
            for (const char c : pem.substr(b + 27, e - b - 27)) {
                if (c != '\r' && c != '\n' && c != ' ') body += c;
            }
            bytes = Base64Decode(body);
        }
    }
    if (bytes.empty()) {
        Error(response, 404, name + " is not there", "The hub has no such issuer file.");
        return;
    }
    response->status = 200;
    response->contentType = name.find(".cer") != std::string::npos ? "application/pkix-cert" : "application/x-pem-file";
    response->body = bytes;
    response->headers.push_back({"content-disposition", "attachment; filename=\"" + name + "\""});
}

void Inspect(const CASSc::HttpRequest& request, CASSc::HttpResponse* response) {
    Json(response, 200, CertInspect::InspectJson(request.body, Arg(request, "name"), g_config.certPaths()));
}

void Sign(const CASSc::HttpRequest& request, CASSc::HttpResponse* response) {
    if (!Authorize(request, response, "sign")) {
        return;
    }
    const CertLayout::HubCertPaths paths = g_config.certPaths();
    CertTool::ClientOptions client;
    if (!ClientOptionsFrom(request, &client, response)) {
        return;
    }
    if (request.body.empty()) {
        Error(response, 400, "no file was sent", "Choose the device's CSR (or CARI request zip), or paste the CSR.");
        return;
    }
    std::string error;
    std::vector<CertTool::SignedItem> items;
    Cari::Tree request_tree;
    Cari::Tree response_tree;
    const bool isZip = request.body.compare(0, 4, "PK\x03\x04") == 0;
    if (isZip) {
        if (!Cari::ReadZip(request.body, &request_tree, &error) ||
            !CertTool::SignCariTree(paths, request_tree, &response_tree, &items, &error)) {
            Audit(request, "sign CARI request refused: " + CASSc::SafeForLog(error));
            Error(response, 400, "the CARI request can't be signed", "See the detail; the file inspector shows "
                  "every problem in the zip.", error);
            return;
        }
        std::string stem = fs::path(Arg(request, "name")).stem().string();
        if (stem.empty() || !CertTool::IsValidLabel(stem)) {
            stem = "cari";
        }
        const std::string suffix = "-request";
        if (stem.size() > suffix.size() && stem.compare(stem.size() - suffix.size(), suffix.size(), suffix) == 0) {
            stem.erase(stem.size() - suffix.size());
        }
        const std::string file = TimestampForFile() + "-" + stem + "-response.zip";
        const fs::path dir = fs::path(paths.certDir) / CARI_RESPONSES_DIR;
        std::error_code ec;
        fs::create_directories(dir, ec);
        std::ofstream(dir / file, std::ios::binary) << Cari::WriteZip(response_tree);
        unsigned signedCount = 0;
        for (const auto& i : items) {
            signedCount += i.signedOk;
        }
        Audit(request, "signed a CARI request: " + std::to_string(signedCount) + " of " + std::to_string(items.size()) +
                           " CSRs -> " + std::string(CARI_RESPONSES_DIR) + "/" + file);
        Json::Array downloads;
        downloads.Add(Json::Object()
                          .Add("name", Json::Str(file))
                          .Add("url", Json::Str("/api/cari/" + file))
                          .Add("private", Json::Bool(IsPrivateFile(dir / file)))
                          .Add("description", Json::Str("the CARI response: every request file, opr-*.pem next to "
                                                        "each signed CSR, cert1/issuer/, errors.txt for the refused"))
                          .Text());
        Json(response, 200, Json::Object()
                                .Add("ok", Json::Bool(true))
                                .Add("mode", Json::Str("cari"))
                                .Add("items", ItemsJson(items))
                                .Add("errors", Json::Str(response_tree.Has("cert1/errors.txt")
                                                             ? response_tree.files.at("cert1/errors.txt") : ""))
                                .Add("downloads", downloads.Text())
                                .Text());
        return;
    }

    const std::string label = CertTool::NextClientLabel(paths.certDir, client);
    if (fs::exists(fs::path(paths.clientsDir) / label / "cert1")) {
        Error(response, 409, "a device folder named \"" + label + "\" already has a certificate",
              "Choose another device name, or download the existing files from \"Device folders\".");
        return;
    }
    std::string folder;
    if (!CertTool::BareCsrToRequest(request.body, client, label, &request_tree, &error) ||
        !CertTool::SignCariTree(paths, request_tree, &response_tree, &items, &error)) {
        Audit(request, "sign refused: " + CASSc::SafeForLog(error));
        Error(response, 400, error, "Use the file inspector to see what the file is and what is wrong with it.");
        return;
    }
    if (items.empty() || !items[0].signedOk) {
        const std::string why = items.empty() ? "nothing to sign" : items[0].error;
        Audit(request, "sign refused: " + CASSc::SafeForLog(why));
        Error(response, 400, "the CSR can't be signed: " + why,
              "Make a new CSR on the device (ECDSA P-256 or RSA 2048+, with a subject).");
        return;
    }
    if (!CertTool::WriteClientFolder(paths, label, response_tree, client.hubUri, &folder, &error)) {
        Error(response, 500, error, "Check that the hub can write to its certificate folder.");
        return;
    }
    Audit(request, "signed a CSR for \"" + label + "\": " + items[0].subject + ", serial " + items[0].serial);
    Json(response, 200, Json::Object()
                            .Add("ok", Json::Bool(true))
                            .Add("mode", Json::Str("csr"))
                            .Add("label", Json::Str(label))
                            .Add("items", ItemsJson(items))
                            .Add("downloads", FolderDownloads(label))
                            .Text());
}

void Generate(const CASSc::HttpRequest& request, CASSc::HttpResponse* response) {
    if (!Authorize(request, response, "generate")) {
        return;
    }
    CertTool::ClientOptions client;
    if (!ClientOptionsFrom(request, &client, response)) {
        return;
    }
    const CertLayout::HubCertPaths paths = g_config.certPaths();
    const std::string label = CertTool::NextClientLabel(paths.certDir, client);
    client.label = label;
    std::string folder;
    std::string error;
    std::vector<CertTool::SignedItem> items;
    if (!CertTool::IssueClientFolder(paths, client, &folder, &items, &error)) {
        Audit(request, "generate refused: " + CASSc::SafeForLog(error));
        Error(response, 400, error, "Choose another device name, or check the hub's CA (see \"The hub\").");
        return;
    }
    Audit(request, "made a key and certificate for \"" + label + "\": serial " +
                       (items.empty() ? std::string("?") : items[0].serial));
    Json(response, 200, Json::Object()
                            .Add("ok", Json::Bool(true))
                            .Add("mode", Json::Str("generate"))
                            .Add("label", Json::Str(label))
                            .Add("items", ItemsJson(items))
                            .Add("downloads", FolderDownloads(label))
                            .Text());
}

void Clients(CASSc::HttpResponse* response) {
    const CertLayout::HubCertPaths paths = g_config.certPaths();
    Json::Array arr;
    std::error_code ec;
    std::vector<std::string> labels;
    for (const auto& entry : fs::directory_iterator(paths.clientsDir, ec)) {
        if (entry.is_directory() && CertTool::IsValidLabel(entry.path().filename().string())) {
            labels.push_back(entry.path().filename().string());
        }
    }
    std::sort(labels.begin(), labels.end());
    for (const std::string& label : labels) {
        const fs::path dir = fs::path(paths.clientsDir) / label;
        std::string opr;
        bool hasKey = false;
        for (auto it = fs::recursive_directory_iterator(dir / "cert1", ec); !ec && it != fs::recursive_directory_iterator();
             it.increment(ec)) {
            const std::string name = it->path().filename().string();
            if (name.compare(0, 4, "opr-") == 0) opr = fs::relative(it->path(), dir, ec).generic_string();
            if (name.compare(0, 4, "key-") == 0) hasKey = true;
        }
        if (opr.empty() && fs::exists(dir / "operational-certificate.pem")) {
            opr = "operational-certificate.pem";  // a folder from an older release
            hasKey = fs::exists(dir / "private-key.pem");
        }
        arr.Add(Json::Object()
                    .Add("label", Json::Str(label))
                    .Add("certificate", Json::Str(opr))
                    .Add("signed", Json::Bool(!opr.empty()))
                    .Add("hasKey", Json::Bool(hasKey))
                    .Add("downloads", FolderDownloads(label))
                    .Text());
    }
    Json(response, 200, Json::Object().Add("clients", arr.Text()).Text());
}

void Download(const CASSc::HttpRequest& request, const fs::path& path, CASSc::HttpResponse* response) {
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
        Error(response, 404, "no such file", "Pick a file from the list - the folder may have been deleted.");
        return;
    }
    if (IsPrivateFile(path)) {
        if (!Authorize(request, response, "download " + path.filename().string())) {
            return;
        }
        Audit(request, "downloaded the private file " + CertLayout::RelativeTo(g_config.certPaths().certDir, path.string()));
    }
    const std::string ext = path.extension().string();
    response->status = 200;
    response->contentType = ext == ".zip" ? "application/zip"
                          : ext == ".pfx" ? "application/x-pkcs12"
                          : ext == ".cer" ? "application/pkix-cert"
                          : ext == ".pem" ? "application/x-pem-file"
                          : "text/plain; charset=utf-8";
    response->body = ReadFile(path);
    response->headers.push_back({"content-disposition", "attachment; filename=\"" + path.filename().string() + "\""});
    response->headers.push_back({"cache-control", "no-store"});
}

std::string EventsJson(uint64_t after) {
    Json::Array arr;
    for (const CASSc::ScDiagnostics::Event& e : CASSc::ScDiagnostics::Since(after)) {
        arr.Add(Json::Object()
                    .Add("sequence", Json::Num((int64_t)e.sequence))
                    .Add("time", Json::Str(e.time))
                    .Add("kind", Json::Str(e.kind))
                    .Add("address", Json::Str(e.address))
                    .Add("subject", Json::Str(e.subject))
                    .Add("issuer", Json::Str(e.issuer))
                    .Add("detail", Json::Str(e.detail))
                    .Text());
    }
    return arr.Text();
}

void Diagnostics(const CASSc::HttpRequest& request, CASSc::HttpResponse* response) {
    const uint64_t after = std::strtoull(Arg(request, "after").c_str(), nullptr, 10);
    Json(response, 200, Json::Object()
                            .Add("events", EventsJson(after))
                            .Add("connected", g_config.connectedDevicesJson ? g_config.connectedDevicesJson() : "[]")
                            .Text());
}

void Report(const CASSc::HttpRequest& request, CASSc::HttpResponse* response) {
    const CertLayout::HubCertPaths paths = g_config.certPaths();
    const Gate gate = DescribeGate(request);
    std::string caError;
    const bool canSign = CertTool::CheckSigningCa(paths, &caError);
    std::string r;
    r += "BACnet/SC hub diagnostic report (no keys or passwords in it)\n";
    r += "============================================================\n";
    r += g_config.appName + " v" + g_config.appVersion + ", CAS BACnet Stack " + g_config.stackVersion + "\n";
    r += "Device: " + g_config.deviceName + " (instance " + std::to_string(g_config.deviceInstance) + ")\n";
    r += "Hub URI(s) for devices:";
    for (const std::string& u : g_config.hubUris()) r += " " + u;
    r += "\nCertificate folder: " + paths.certDir + " (" + paths.KindName() + ")\n";
    r += "Hub key password-protected: " + std::string(gate.passwordProtectedKey ? "yes" : "no") + "\n";
    r += "Can sign devices: " + std::string(canSign ? "yes" : "no - " + caError) + "\n\n";
    r += "--- Hub certificate (" + CertLayout::RelativeTo(paths.certDir, paths.operationalCertificate) + ") ---\n";
    r += CertInspect::CertificateFileJson(paths.operationalCertificate, "hub", true, paths) + "\n\n";
    r += "--- Issuer slot 1 ---\n" + CertInspect::CertificateFileJson(paths.issuerCertificate1, "iss-1", false, paths) + "\n\n";
    r += "--- Connected devices ---\n" + (g_config.connectedDevicesJson ? g_config.connectedDevicesJson() : "[]") + "\n\n";
    r += "--- Recent BACnet/SC connection events (oldest first) ---\n";
    for (const CASSc::ScDiagnostics::Event& e : CASSc::ScDiagnostics::Since(0)) {
        r += e.time + "  " + e.kind + "  " + e.address + "  " + e.subject + (e.issuer.empty() ? "" : " (issuer " + e.issuer + ")") +
             "  " + e.detail + "\n";
    }
    response->status = 200;
    response->contentType = "text/plain; charset=utf-8";
    response->body = r;
    response->headers.push_back({"cache-control", "no-store"});
}

}  // namespace

void Configure(const Config& config) {
    g_config = config;
}

bool HandleRoute(const CASSc::HttpRequest& request, CASSc::HttpResponse* response) {
    const std::string& path = request.path;
    const bool get = request.method == "GET";
    const bool post = request.method == "POST";

    if (get && (path == "/setup" || path == "/setup/")) {
        response->status = 200;
        response->contentType = "text/html; charset=utf-8";
        response->body = SETUP_PAGE_HTML;
        response->headers.push_back({"cache-control", "no-store"});
        response->headers.push_back({"x-content-type-options", "nosniff"});
        response->headers.push_back({"content-security-policy",
                                     "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                                     "img-src data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'"});
        return true;
    }
    if (get && path == "/api/setup/info") { Info(request, response); return true; }
    static const std::string kIssuerPrefix = "/api/setup/issuer/";
    if (get && path.compare(0, kIssuerPrefix.size(), kIssuerPrefix) == 0) {
        IssuerFile(path.substr(kIssuerPrefix.size()), response);
        return true;
    }
    if (post && path == "/api/inspect") { Inspect(request, response); return true; }
    if (post && path == "/api/check-password") {
        if (Authorize(request, response, "check the password")) {
            Json(response, 200, Json::Object().Add("ok", Json::Bool(true)).Text());
        }
        return true;
    }
    if (post && path == "/api/sign") { Sign(request, response); return true; }
    if (post && path == "/api/generate") { Generate(request, response); return true; }
    if (get && path == "/api/clients") { Clients(response); return true; }
    if (get && path == "/api/diagnostics") { Diagnostics(request, response); return true; }
    if (get && path == "/api/report") { Report(request, response); return true; }
    if (get && path.compare(0, 14, "/api/download/") == 0) {
        const std::string rest = path.substr(14);
        const size_t slash = rest.find('/');
        const std::string label = rest.substr(0, slash);
        const std::string rel = slash == std::string::npos ? std::string() : rest.substr(slash + 1);
        if (!CertTool::IsValidLabel(label) || !SafeRelative(rel)) {
            Error(response, 400, "bad download path", "Use the links the page gives.");
            return true;
        }
        Download(request, fs::path(g_config.certPaths().clientsDir) / label / rel, response);
        return true;
    }
    if (get && path.compare(0, 10, "/api/cari/") == 0) {
        const std::string file = path.substr(10);
        if (!SafeRelative(file) || file.find('/') != std::string::npos) {
            Error(response, 400, "bad download path", "Use the links the page gives.");
            return true;
        }
        Download(request, fs::path(g_config.certPaths().certDir) / CARI_RESPONSES_DIR / file, response);
        return true;
    }
    if (path.compare(0, 5, "/api/") == 0) {
        Error(response, get || post ? 404 : 405, "unknown API path " + path, "See docs/manual.md, \"Set-up guide API\".");
        return true;
    }
    return false;
}

}  // namespace CertPortal
