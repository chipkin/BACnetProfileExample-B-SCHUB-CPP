// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
// Implementation of ScTransport. See ScTransport.h for the contract.
#include "ScTransport.h"

#include "CASExampleLog.h"

#include <libwebsockets.h>
#include <openssl/ssl.h>    // SSL_OP_NO_TLSv1* - TLS 1.3-only restriction
#include <openssl/x509.h>   // startup cert diagnostics (Item 3) + client-cert-verify logging (Item 1)
#include <openssl/x509v3.h> // GENERAL_NAME_print - SAN entries, startup cert diagnostics (Item 3)
#include <openssl/pem.h>    // PEM_read_X509/PEM_read_PrivateKey - startup cert diagnostics (Item 3)
#include <openssl/bio.h>    // in-memory BIO - SAN entries via GENERAL_NAME_print (Item 3)
#include <openssl/err.h>    // ERR_clear_error - CRL loading (issue #15)

#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>

#if defined(_WIN32)
// lws_sockfd_type is SOCKET on Windows (libwebsockets.h) - sockaddr_storage/
// getpeername/ntohs come from winsock2.h/ws2tcpip.h, already pulled in
// transitively by libwebsockets.h ahead of this include (see
// AllowNewConnectionAttempt's own comment on the windows.h/min-max footgun
// for why this repo already knows libwebsockets.h drags windows.h in).
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace CASSc {

namespace {

// BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH from
// submodules/cas-bacnet-stack/source/BACnetStackConstants.h - a frame the
// stack could never accept anyway must never be queued for it (plan fact 8).
// As of the stack pin bump that closed cas-bacnet-stack#2225 (commit 2021e29f,
// "SC ingress buffer/ceilings now accept a maximum-size Annex AB frame"), this
// constant is gated on STACK_OPTION_DATA_LINK_LAYER_SC (compiled in for this
// example) and is now 1600 bytes - reaching ANSI/ASHRAE 135 Annex AB's
// 1600-octet minimum BVLC-SC relay size exactly (it was previously pinned at
// 1497, 103 bytes short of that minimum). Not #include-d directly:
// BACnetStackConstants.h is an internal stack header, not part of the public
// adapter surface this example otherwise depends on; the value is stable and
// cross-checked against source on every phase of this plan - see
// docs/bacnet-sc-transport-plan.md.
const std::size_t kMaxIngressBytes = 1600;

// RETRYING lws_create_context. A failed lws_create_context() (the SC port
// briefly in use, a certificate file that doesn't parse yet) is retried: the
// stack calls StartListening() again every Tick and Connect() again on its own
// reconnect timer. That used to crash the process (issue #13), so an earlier
// release refused to retry at all until restart (issue #28). The crash was
// OpenSSL being torn down by the last TLS lws_context's destroy, not the retry
// itself - EnsureTlsLifetimeContext() (below) keeps one TLS context alive for
// the whole process, which makes a failed-then-retried create safe (verified:
// port in use then freed, unparseable certificate then fixed, both recover
// without a restart). The listener waits kListenRetryInterval between failed
// attempts so a port that stays busy is not re-bound 30 times a second.
const std::chrono::seconds kListenRetryInterval(5);

bool FileReadable(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    std::ifstream f(path, std::ios::binary);
    return f.good();
}

// Parses "wss://host:port/path...". Only wss:// is accepted (BACnet/SC
// requires it - AddBACnetSCAcceptUri's own doc comment). host may be empty
// (e.g. "wss://:47819/") or "0.0.0.0", both of which mean "bind all
// interfaces" - both map to a NULL lws iface (listener use only).
// outPath is optional (nullptr for the listener, which does not route by
// path); when non-null it is set to the path component, defaulting to "/"
// when the URI has none - Connect() (below) needs it for
// lws_client_connect_info::path.
bool ParseWssUri(const std::string& uri, std::string* outHost, uint16_t* outPort,
                 std::string* outPath = nullptr) {
    static const char kScheme[] = "wss://";
    const std::size_t schemeLen = sizeof(kScheme) - 1;
    if (uri.compare(0, schemeLen, kScheme) != 0) {
        return false;
    }
    std::size_t hostStart = schemeLen;
    std::size_t pathSlash = uri.find('/', hostStart);
    std::string authority = (pathSlash == std::string::npos)
        ? uri.substr(hostStart)
        : uri.substr(hostStart, pathSlash - hostStart);
    if (outPath != nullptr) {
        *outPath = (pathSlash == std::string::npos) ? "/" : uri.substr(pathSlash);
    }
    if (authority.empty()) {
        return false;
    }
    const std::size_t colon = authority.rfind(':');
    if (colon == std::string::npos || colon + 1 >= authority.size()) {
        return false;  // a port is required - this example never guesses one
    }
    const std::string host = authority.substr(0, colon);
    const std::string portStr = authority.substr(colon + 1);
    char* end = nullptr;
    const long port = strtol(portStr.c_str(), &end, 10);
    if (end == portStr.c_str() || *end != '\0' || port <= 0 || port > 65535) {
        return false;
    }
    *outHost = host;
    *outPort = static_cast<uint16_t>(port);
    return true;
}

// True if `headerValue` (a comma-separated Sec-WebSocket-Protocol request
// list, possibly with spaces) contains `wanted` as one whole token. Used
// because lws's own negotiation can otherwise silently accept a connection on
// protocols[0] even when the client asked for something else entirely - a
// known footgun this example does not want (V1's "wrong subprotocol is
// rejected" case depends on this check, not on lws's default behaviour).
bool SubprotocolListContains(const char* headerValue, const std::string& wanted) {
    if (headerValue == nullptr) {
        return false;
    }
    std::string list(headerValue);
    std::size_t pos = 0;
    while (pos <= list.size()) {
        std::size_t comma = list.find(',', pos);
        std::string token = (comma == std::string::npos) ? list.substr(pos) : list.substr(pos, comma - pos);
        // Trim surrounding whitespace.
        std::size_t start = token.find_first_not_of(" \t");
        std::size_t stop = token.find_last_not_of(" \t");
        if (start != std::string::npos) {
            token = token.substr(start, stop - start + 1);
            if (token == wanted) {
                return true;
            }
        }
        if (comma == std::string::npos) {
            break;
        }
        pos = comma + 1;
    }
    return false;
}

// Diagnostic Item 2: best-effort "ip:port" for a peer wsi. lws_get_peer_simple()
// gives only the IP (verified against its own doc comment in
// lws-network-helper.h - "provides a 123.123.123.123 type IP address", no
// port); lws has no higher-level accessor for the port itself, so this falls
// back to a raw getpeername() on the underlying socket (lws_get_socket_fd()) -
// the same information a peer's own OS-level connection table has, just not
// exposed through lws's own API.
//
// Not usable from LWS_CALLBACK_FILTER_NETWORK_CONNECTION: there, wsi is still
// the LISTENING socket, so lws_get_peer_simple()/getpeername() have no peer
// (on failure lws_get_peer_simple() writes its own error text, such as
// "getpeername: wsaerrno 10057", into the buffer - the digit-or-colon check
// below keeps that text out of the log). That callback gets the peer from
// struct lws_filter_network_conn_args instead - see AddressFromSockaddr().
std::string PeerAddressPort(lws* wsi) {
    char ip[64] = {0};
    lws_get_peer_simple(wsi, ip, sizeof(ip));
    const bool looksLikeAddress = ip[0] != '\0' && (std::isdigit(static_cast<unsigned char>(ip[0])) || ip[0] == ':');
    if (!looksLikeAddress) {
        std::strcpy(ip, "?");
    }
    uint16_t port = 0;
    const lws_sockfd_type fd = lws_get_socket_fd(wsi);
    sockaddr_storage addr;
    std::memset(&addr, 0, sizeof(addr));
    socklen_t addrLen = sizeof(addr);
    if (getpeername(fd, reinterpret_cast<sockaddr*>(&addr), &addrLen) == 0) {
        if (addr.ss_family == AF_INET) {
            port = ntohs(reinterpret_cast<sockaddr_in*>(&addr)->sin_port);
        } else if (addr.ss_family == AF_INET6) {
            port = ntohs(reinterpret_cast<sockaddr_in6*>(&addr)->sin6_port);
        }
    }
    char result[80];
    if (port != 0) {
        std::snprintf(result, sizeof(result), "%s:%u", ip, (unsigned)port);
    } else {
        std::snprintf(result, sizeof(result), "%s:?", ip);
    }
    return std::string(result);
}

// The numeric address ("192.0.2.7", "2001:db8::5") in a sockaddr_storage - the
// form struct lws_filter_network_conn_args gives LWS_CALLBACK_FILTER_NETWORK_
// CONNECTION. An IPv4-mapped IPv6 address is shown as plain IPv4, so the same
// host always gets the same rate-limit bucket.
std::string AddressFromSockaddr(const sockaddr_storage& addr) {
    char text[INET6_ADDRSTRLEN] = {0};
    if (addr.ss_family == AF_INET) {
        const sockaddr_in* in4 = reinterpret_cast<const sockaddr_in*>(&addr);
        inet_ntop(AF_INET, const_cast<in_addr*>(&in4->sin_addr), text, sizeof(text));
    } else if (addr.ss_family == AF_INET6) {
        const sockaddr_in6* in6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        inet_ntop(AF_INET6, const_cast<in6_addr*>(&in6->sin6_addr), text, sizeof(text));
    }
    std::string result(text);
    if (result.compare(0, 7, "::ffff:") == 0 && result.find('.') != std::string::npos) {
        result = result.substr(7);
    }
    return result.empty() ? std::string("?") : result;
}

// Refills a token bucket for the time since it was last touched (at `rate`
// tokens a second, holding at most `rate`), then takes one token if there is
// one. A bucket that has never been touched starts full.
bool TakeToken(double* tokens, std::chrono::steady_clock::time_point* lastRefill, const uint32_t rate,
               const std::chrono::steady_clock::time_point now) {
    const double capacity = static_cast<double>(rate);
    if (*lastRefill == std::chrono::steady_clock::time_point()) {
        *tokens = capacity;
    } else {
        const double refilled = *tokens + std::chrono::duration<double>(now - *lastRefill).count() * capacity;
        // NOT std::min(): libwebsockets.h pulls in <windows.h> without
        // NOMINMAX, whose min/max macros shadow std::min/std::max.
        *tokens = (refilled < capacity) ? refilled : capacity;
    }
    *lastRefill = now;
    if (*tokens >= 1.0) {
        *tokens -= 1.0;
        return true;
    }
    return false;
}

// ---- BACnet/SC message identity (audit trail, issue #21) -------------------
// Just enough of the BVLC-SC header (135-2024 AB.2.1) to find a
// Connect-Request's payload: function, control flags, message ID, optional
// originating/destination VMACs, optional destination/data header options.
// The stack does all real BACnet/SC processing; this only reads identity.
const uint8_t kBvlcResult = 0x00;
const uint8_t kBvlcConnectRequest = 0x06;
const uint8_t kBvlcConnectAccept = 0x07;

// Returns the offset of the payload, or 0 if the header is malformed.
std::size_t BvlcPayloadOffset(const uint8_t* data, const std::size_t len) {
    if (len < 4) {
        return 0;
    }
    const uint8_t flags = data[1];
    std::size_t offset = 4;                    // function, control flags, message ID
    if (flags & 0x08) offset += 6;             // originating virtual address
    if (flags & 0x04) offset += 6;             // destination virtual address
    for (int optionList = 0; optionList < 2; ++optionList) {
        const bool present = (optionList == 0) ? (flags & 0x02) != 0 : (flags & 0x01) != 0;
        bool more = present;
        while (more) {
            if (offset >= len) {
                return 0;
            }
            const uint8_t marker = data[offset++];
            more = (marker & 0x80) != 0;       // More Options
            if (marker & 0x20) {               // Header Data Flag: 2-octet length + data
                if (offset + 2 > len) {
                    return 0;
                }
                offset += 2 + ((static_cast<std::size_t>(data[offset]) << 8) | data[offset + 1]);
            }
        }
    }
    return offset <= len ? offset : 0;
}

std::string HexBytes(const uint8_t* data, const std::size_t len, const char* separator) {
    std::string out;
    char byte[4];
    for (std::size_t i = 0; i < len; ++i) {
        std::snprintf(byte, sizeof(byte), "%02x", data[i]);
        if (i > 0) {
            out += separator;
        }
        out += byte;
    }
    return out;
}

// A 16-octet device UUID as 8-4-4-4-12 hex.
std::string FormatUuid(const uint8_t* uuid) {
    return HexBytes(uuid, 4, "") + "-" + HexBytes(uuid + 4, 2, "") + "-" + HexBytes(uuid + 6, 2, "") + "-" +
           HexBytes(uuid + 8, 2, "") + "-" + HexBytes(uuid + 10, 6, "");
}

// The subject of the certificate the peer presented in the TLS handshake, as
// one line ("O=Example Site, CN=AHU-3 controller"), or "?" if there is none.
std::string PeerCertificateSubject(lws* wsi) {
    SSL* ssl = lws_get_ssl(wsi);
    X509* cert = (ssl != nullptr) ? SSL_get1_peer_certificate(ssl) : nullptr;
    if (cert == nullptr) {
        return "?";
    }
    std::string subject = "?";
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio != nullptr) {
        X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
        char* text = nullptr;
        const long textLen = BIO_get_mem_data(bio, &text);
        if (textLen > 0) {
            subject.assign(text, static_cast<std::size_t>(textLen));
        }
        BIO_free(bio);
    }
    X509_free(cert);
    return subject;
}

// Diagnostic Item 1: makes a rejected mTLS handshake visible. Before this, a
// client whose certificate did not chain to m_tls.caCertPath failed inside
// OpenSSL's own verification, deep under lws_create_context's
// LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT enforcement, before
// LWS_CALLBACK_ESTABLISHED or any other application callback ever fired - the
// ONLY trace was a raw, unformatted libwebsockets debug line, if lws's own log
// level happened to be verbose enough to print it. Investigated (per this
// task's own instructions) whether LWS_CALLBACK_SSL_INFO /
// ssl_info_event_mask could serve this instead: read against the pinned lws
// 4.5.8 headers (lws-context-vhost.h), that mask only carries OpenSSL's
// SSL_CB_ALERT-style info-callback events (TLS protocol-level alert
// send/receive), not a client-cert verification outcome or the failing cert
// itself - the wrong tool for this. What the pinned header DOES expose,
// exactly for this purpose, is LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION
// (reason 23, lws-callbacks.h): "if the libwebsockets vhost was created with
// [...] LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT [already set,
// StartListening() below], this callback is generated during OpenSSL
// verification of the cert sent from the client [...] user is the x509_ctx,
// in is the ssl pointer and len is preverify_ok". This is a direct,
// lws-provided tap on the SAME OpenSSL SSL_CTX_set_verify callback the
// "install our own SSL_CTX_set_verify directly" fallback this task's
// instructions called out would have had to install by hand - lws already
// wires it up, so that heavier fallback was not needed. The one wrinkle
// (verified against the SAME header comment): "the libwebsockets context and
// wsi are both NULL during this callback" - LwsServerCallbackTrampoline below
// special-cases this reason BEFORE its normal lws_get_context(wsi) lookup
// (which would otherwise discard the callback outright, wsi being null - see
// the trampoline's own comment).
//
// This function does not change the accept/reject DECISION - it mirrors
// OpenSSL's own preverify_ok back to lws unchanged (return 0/1 exactly as
// preverify_ok dictates, matching the reason's own "return 0 to mean the cert
// is OK or 1 to fail it" contract) - the mandatory chain check
// LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT already performs is
// unaffected either way. It only adds the missing observability: on a
// failure, the OpenSSL verify error (X509_STORE_CTX_get_error, decoded via
// X509_verify_cert_error_string - e.g. "unable to get local issuer
// certificate" for a cert not signed by our CA) and the failing cert's own
// subject/issuer CN (X509_STORE_CTX_get_current_cert - the cert AT THE DEPTH
// verification failed, which for a self-signed rogue cert is the peer's own
// presented cert).
int LogClientCertVerificationResult(void* user, void* in, std::size_t len) {
    (void)in;  // the SSL* - not needed; X509_STORE_CTX already carries the failing cert + error
    const int preverifyOk = static_cast<int>(len);
    if (preverifyOk) {
        return 0;  // OpenSSL's own chain verification already passed this cert - nothing to log
    }
    X509_STORE_CTX* x509Ctx = static_cast<X509_STORE_CTX*>(user);
    std::string subjectCn = "<unknown>";
    std::string issuerCn = "<unknown>";
    int errorCode = -1;
    const char* errorText = "unknown error (no X509_STORE_CTX available)";
    if (x509Ctx != nullptr) {
        errorCode = X509_STORE_CTX_get_error(x509Ctx);
        errorText = X509_verify_cert_error_string(errorCode);
        X509* cert = X509_STORE_CTX_get_current_cert(x509Ctx);
        if (cert != nullptr) {
            char buf[256] = {0};
            X509_NAME* subject = X509_get_subject_name(cert);
            if (subject != nullptr && X509_NAME_get_text_by_NID(subject, NID_commonName, buf, sizeof(buf)) > 0) {
                subjectCn = buf;
            }
            char issuerBuf[256] = {0};
            X509_NAME* issuer = X509_get_issuer_name(cert);
            if (issuer != nullptr && X509_NAME_get_text_by_NID(issuer, NID_commonName, issuerBuf, sizeof(issuerBuf)) > 0) {
                issuerCn = issuerBuf;
            }
        }
    }
    CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
        "SC TLS handshake REJECTED - client certificate failed verification: \"%s\" (OpenSSL error code %d); "
        "presented cert subject CN=\"%s\" issuer CN=\"%s\"",
        errorText, errorCode, subjectCn.c_str(), issuerCn.c_str());
    return 1;  // fail the cert - mirrors OpenSSL's own preverify_ok=0 decision, does not override it
}

// Diagnostic Item 3: human-readable "N day(s) ago"/"N day(s) from now" from
// an ASN1_TIME, via ASN1_TIME_diff(..., NULL /* from=now */, ...) rather than
// logging the raw ASN1_TIME (a GeneralizedTime/UTCTime byte string - not
// something an operator should have to decode by hand). Deliberately does
// NOT say "EXPIRED" for a past date by itself - a PAST notBefore is normal
// (every valid cert's validity period started in the past); only the caller
// (LogOneCertificate below, for notAfter specifically) knows whether "in the
// past" means "expired" for the field it is describing.
std::string DaysRelativeToNow(const ASN1_TIME* when) {
    if (when == nullptr) {
        return "<unknown>";
    }
    int days = 0;
    int seconds = 0;
    if (!ASN1_TIME_diff(&days, &seconds, nullptr, when)) {
        return "<unparseable>";
    }
    if (days < 0 || (days == 0 && seconds < 0)) {
        const int pastDays = (days < 0) ? -days : 0;
        return std::to_string(pastDays) + " day(s) ago";
    }
    return std::to_string(days) + " day(s) from now";
}

// Diagnostic Item 3: logs one X.509 certificate's subject/issuer CN,
// notBefore/notAfter (as a day count via DaysUntil above - Warning if
// under 30 days or already expired), and SAN entries (Info; this transport's
// connector deliberately skips hostname checking - see ScTransport::Connect's
// own comment and sc_transport/README.md - so SAN entries are informational
// here, not used for any policy decision). `label` distinguishes the log
// lines when this is called for more than one file (operational cert vs. CA)
// in the same LogCertificateDiagnostics call below.
void LogOneCertificate(const std::string& label, X509* cert) {
    char subjectCn[256] = {0};
    char issuerCn[256] = {0};
    X509_NAME* subject = X509_get_subject_name(cert);
    X509_NAME* issuer = X509_get_issuer_name(cert);
    const bool hasSubjectCn = subject != nullptr &&
        X509_NAME_get_text_by_NID(subject, NID_commonName, subjectCn, sizeof(subjectCn)) > 0;
    const bool hasIssuerCn = issuer != nullptr &&
        X509_NAME_get_text_by_NID(issuer, NID_commonName, issuerCn, sizeof(issuerCn)) > 0;

    const ASN1_TIME* notBefore = X509_get0_notBefore(cert);
    const ASN1_TIME* notAfter = X509_get0_notAfter(cert);
    int daysLeft = 0, secsLeft = 0;
    const bool haveExpiry = notAfter != nullptr && ASN1_TIME_diff(&daysLeft, &secsLeft, nullptr, notAfter) != 0;
    const bool expiringSoon = haveExpiry && (daysLeft < 30);
    CASExampleHelper::Log(expiringSoon ? CASExampleHelper::LogLevel::Warning : CASExampleHelper::LogLevel::Info,
        "cert diagnostics: %s subject CN=\"%s\" issuer CN=\"%s\" notBefore=(%s) notAfter=(%s)%s",
        label.c_str(), hasSubjectCn ? subjectCn : "<none>", hasIssuerCn ? issuerCn : "<none>",
        DaysRelativeToNow(notBefore).c_str(), DaysRelativeToNow(notAfter).c_str(),
        expiringSoon ? " - EXPIRING SOON OR ALREADY EXPIRED (notAfter)" : "");

    GENERAL_NAMES* sans = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (sans == nullptr) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
            "cert diagnostics: %s has no Subject Alternative Name extension "
            "(not a problem - this transport's connector skips hostname checking, see ScTransport::Connect)",
            label.c_str());
    } else {
        BIO* bio = BIO_new(BIO_s_mem());
        if (bio != nullptr) {
            const int count = sk_GENERAL_NAME_num(sans);
            for (int i = 0; i < count; ++i) {
                if (i > 0) {
                    BIO_printf(bio, ", ");
                }
                GENERAL_NAME_print(bio, sk_GENERAL_NAME_value(sans, i));
            }
            char* data = nullptr;
            const long dataLen = BIO_get_mem_data(bio, &data);
            const std::string sanText(data != nullptr ? data : "", dataLen > 0 ? static_cast<std::size_t>(dataLen) : 0);
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                "cert diagnostics: %s SAN entries: %s", label.c_str(), sanText.c_str());
            BIO_free(bio);
        }
        GENERAL_NAMES_free(sans);
    }
}

// ---- Certificate revocation (issue #15) -------------------------------------
// Loads every CRL in `path` into a TLS context's certificate store and turns
// on revocation checking of the peer's certificate (X509_V_FLAG_CRL_CHECK -
// the peer's own certificate; its CA certificates are trusted as configured).
// Called from the LWS_CALLBACK_OPENSSL_LOAD_EXTRA_{SERVER,CLIENT}_VERIFY_CERTS
// callbacks, which lws fires once per TLS context as it is created, so a
// ReloadCredentials() picks up a changed file. Returns false only when the
// file exists but holds no CRL at all - the caller then fails the context
// (fail closed, rather than silently accepting revoked devices).
bool LoadRevocationList(SSL_CTX* sslCtx, const std::string& path, const char* role) {
    if (sslCtx == nullptr || path.empty() || !FileReadable(path)) {
        return true;  // no CRL configured - nothing to check against
    }
    X509_STORE* store = SSL_CTX_get_cert_store(sslCtx);
    BIO* bio = BIO_new_file(path.c_str(), "r");
    int count = 0;
    X509_CRL* crl = nullptr;
    while (bio != nullptr && (crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr)) != nullptr) {
        char issuer[256] = {0};
        X509_NAME_get_text_by_NID(X509_CRL_get_issuer(crl), NID_commonName, issuer, sizeof(issuer));
        const ASN1_TIME* nextUpdate = X509_CRL_get0_nextUpdate(crl);
        int days = 0;
        int seconds = 0;
        const bool expired = nextUpdate != nullptr && ASN1_TIME_diff(&days, &seconds, nullptr, nextUpdate) &&
                             (days < 0 || (days == 0 && seconds < 0));
        const STACK_OF(X509_REVOKED)* revoked = X509_CRL_get_REVOKED(crl);
        CASExampleHelper::Log(expired ? CASExampleHelper::LogLevel::Warning : CASExampleHelper::LogLevel::Info,
            "SC revocation (%s): CRL from \"%s\", %d certificate(s) revoked, next update %s%s", role,
            issuer[0] != '\0' ? issuer : "?", revoked != nullptr ? sk_X509_REVOKED_num(revoked) : 0,
            DaysRelativeToNow(nextUpdate).c_str(),
            expired ? " - EXPIRED: every certificate from this issuer is refused until a new CRL is installed" : "");
        if (X509_STORE_add_crl(store, crl) == 1) {  // the store takes its own reference
            ++count;
        }
        X509_CRL_free(crl);
    }
    ERR_clear_error();  // the read loop always ends with a harmless "no start line"
    if (bio != nullptr) {
        BIO_free(bio);
    }
    if (count == 0) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Error,
            "SC revocation (%s): \"%s\" exists but holds no PEM CRL - refusing to start TLS until it is "
            "fixed or removed", role, path.c_str());
        return false;
    }
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    return true;
}

// Diagnostic Item 3: startup certificate self-diagnosis, called once per
// StartListening()/Connect() (NOT per-connection) - see the header comment on
// each call site below. Loads m_tls.certPath/caCertPath with OpenSSL's X.509
// API and logs what a misconfigured cert/key/CA would otherwise only surface
// as the generic "lws_create_context failed [...] cert files malformed?"
// guess. Runs even when FileReadable() already passed (a file that EXISTS but
// is wrong - expired, mismatched key, wrong CA - is exactly what this
// diagnoses; the per-file missing/unreadable check, Item 4, is a separate,
// earlier gate).
//
// Returns false ONLY for the one case this function can prove with certainty
// is broken - both files parsed fine as PEM, and X509_check_private_key()
// definitively says they don't match. The caller (StartListening()/Connect())
// then skips lws_create_context for this attempt: it could only fail, and the
// next retry re-checks the files, so fixing the pair under --sc-cert-dir takes
// effect without a restart. Every OTHER outcome here (a file that fails to
// PARSE as PEM) is just logged - lws_create_context remains the authority for
// every case this function cannot prove is broken with certainty.
bool LogCertificateDiagnostics(const ScTlsFiles& tls) {
    // Rate-limited to once per kMinLogInterval, not once per call: the stack
    // retries StartListening()/Connect() while they fail, and an unfixed
    // cert/key mismatch would otherwise print this multi-line diagnosis on
    // every retry. The X.509 parse and X509_check_private_key() below still
    // run every call (cheap, and the caller needs an up-to-date answer to
    // notice a live fix) - only the CASExampleHelper::Log calls are gated.
    static std::chrono::steady_clock::time_point lastLogTime;
    static bool haveLoggedOnce = false;
    const auto now = std::chrono::steady_clock::now();
    const auto kMinLogInterval = std::chrono::seconds(30);
    const bool shouldLog = !haveLoggedOnce || (now - lastLogTime) >= kMinLogInterval;
    if (shouldLog) {
        lastLogTime = now;
        haveLoggedOnce = true;
    }

    bool confirmedMismatch = false;

    FILE* certFile = fopen(tls.certPath.c_str(), "rb");
    X509* cert = (certFile != nullptr) ? PEM_read_X509(certFile, nullptr, nullptr, nullptr) : nullptr;
    if (certFile != nullptr) {
        fclose(certFile);
    }
    if (cert == nullptr) {
        if (shouldLog) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                "cert diagnostics: could not parse \"%s\" as a PEM X.509 certificate - skipping self-diagnosis "
                "(lws_create_context will report whether this actually blocks startup)", tls.certPath.c_str());
        }
    } else {
        if (shouldLog) {
            LogOneCertificate("operational certificate (\"" + tls.certPath + "\")", cert);
        }

        FILE* keyFile = fopen(tls.keyPath.c_str(), "rb");
        EVP_PKEY* pkey = (keyFile != nullptr) ? PEM_read_PrivateKey(keyFile, nullptr, nullptr, nullptr) : nullptr;
        if (keyFile != nullptr) {
            fclose(keyFile);
        }
        if (pkey == nullptr) {
            if (shouldLog) {
                CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                    "cert diagnostics: could not parse \"%s\" as a PEM private key - cannot check it against "
                    "\"%s\"", tls.keyPath.c_str(), tls.certPath.c_str());
            }
        } else {
            // The single most common real misconfiguration this diagnoses
            // (per this task's own instructions) - a cert/key pair that does
            // not actually match, previously indistinguishable from every
            // other "cert files malformed?" failure.
            const bool matches = X509_check_private_key(cert, pkey) == 1;
            if (shouldLog) {
                CASExampleHelper::Log(matches ? CASExampleHelper::LogLevel::Info : CASExampleHelper::LogLevel::Error,
                    "cert diagnostics: private key \"%s\" %s the public key in \"%s\"", tls.keyPath.c_str(),
                    matches ? "MATCHES" : "DOES NOT MATCH", tls.certPath.c_str());
            }
            confirmedMismatch = !matches;
            EVP_PKEY_free(pkey);
        }
        X509_free(cert);
    }

    FILE* caFile = fopen(tls.caCertPath.c_str(), "rb");
    X509* caCert = (caFile != nullptr) ? PEM_read_X509(caFile, nullptr, nullptr, nullptr) : nullptr;
    if (caFile != nullptr) {
        fclose(caFile);
    }
    if (caCert == nullptr) {
        if (shouldLog) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                "cert diagnostics: could not parse \"%s\" as a PEM X.509 certificate - skipping self-diagnosis",
                tls.caCertPath.c_str());
        }
    } else {
        if (shouldLog) {
            LogOneCertificate("CA certificate (\"" + tls.caCertPath + "\")", caCert);
        }
        X509_free(caCert);
    }

    return !confirmedMismatch;
}

// Diagnostic Item 4: names specifically which of cert/key/ca is missing or
// unreadable, instead of bundling all three into one message regardless of
// which actually failed. Returns "" (nothing missing) or a
// "cert=\"...\"[, key=\"...\"][, ca=\"...\"]"-style fragment naming only the
// file(s) that actually failed FileReadable() - shared by StartListening()
// and Connect(), whose per-file checks were previously identical bundled
// messages.
std::string DescribeMissingTlsFiles(const ScTlsFiles& tls) {
    std::string result;
    if (!FileReadable(tls.certPath)) {
        result += "cert=\"" + tls.certPath + "\"";
    }
    if (!FileReadable(tls.keyPath)) {
        if (!result.empty()) {
            result += ", ";
        }
        result += "key=\"" + tls.keyPath + "\"";
    }
    if (!FileReadable(tls.caCertPath)) {
        if (!result.empty()) {
            result += ", ";
        }
        result += "ca=\"" + tls.caCertPath + "\"";
    }
    return result;
}

// The single, process-wide instance currently bound to the listener context.
// lws hands callbacks to a plain C function pointer with no way to pass a
// C++ `this` other than through lws_context_user()/info.user, which we do
// set per-context - this pointer exists only so the trampoline function below
// has something to call `HandleServerCallback` through without becoming a
// member function itself (lws_protocols::callback must be a free function).
int LwsServerCallbackTrampoline(lws* wsi, lws_callback_reasons reason, void* user, void* in, std::size_t len) {
    // LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION (reason 23) fires
    // with wsi AND context both NULL (lws's own doc comment, lws-callbacks.h -
    // verified against the pinned 4.5.8 header) - handled BEFORE the
    // lws_get_context(wsi) lookup below, which would otherwise silently
    // discard it (wsi is null, so ctx would be null, so this function would
    // return 0 without ever reaching HandleServerCallback). See
    // LogClientCertVerificationResult's own comment above for why this reason
    // is used at all (Item 1 - making a rejected mTLS handshake visible).
    if (reason == LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION) {
        return LogClientCertVerificationResult(user, in, len);
    }
    lws_context* ctx = wsi != nullptr ? lws_get_context(wsi) : nullptr;
    if (ctx == nullptr) {
        return 0;  // called before/without a context (e.g. protocol init on a template wsi) - nothing to do
    }
    ScTransport* self = static_cast<ScTransport*>(lws_context_user(ctx));
    if (self == nullptr) {
        return 0;
    }
    return self->HandleServerCallback(wsi, static_cast<int>(reason), user, in, len);
}

// Connector-half sibling of the above - every ClientConnection's lws_context
// also sets info.user = this (Connect(), below), so the same "context user
// pointer, not a static singleton" pattern applies here too.
int LwsClientCallbackTrampoline(lws* wsi, lws_callback_reasons reason, void* user, void* in, std::size_t len) {
    lws_context* ctx = wsi != nullptr ? lws_get_context(wsi) : nullptr;
    if (ctx == nullptr) {
        return 0;
    }
    ScTransport* self = static_cast<ScTransport*>(lws_context_user(ctx));
    if (self == nullptr) {
        return 0;
    }
    return self->HandleClientCallback(wsi, static_cast<int>(reason), user, in, len);
}

}  // namespace

ScTransport::ScTransport() {}

ScTransport::~ScTransport() {
    DestroyListenerContext();
    // Outside of any lws callback (this is the destructor) - safe to destroy
    // every client context directly, unlike HandleClientCallback (see
    // DestroyClientContext's comment).
    for (auto& kv : m_clients) {
        DestroyClientContext(kv.second);
    }
    m_clients.clear();
    delete[] m_clientProtocols;
    m_clientProtocols = nullptr;
}

// -----------------------------------------------------------------------------
// Keeping OpenSSL alive for the whole process.
//
// Destroying an lws_context created with LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT
// tears down OpenSSL's global state for the WHOLE process when it is the last
// such context alive. Confirmed with a stand-alone probe against this
// project's vcpkg libwebsockets + OpenSSL 3: after lws_context_destroy(),
// PEM_read_bio_X509 fails, and the next lws_create_context() crashes with an
// access violation. That is the root cause of issue #13's "retrying
// lws_create_context crashes", and it broke any listener restart - the stack
// stopping and restarting the SC port, or a certificate reload
// (ReloadCredentials()).
//
// The fix: one TLS-initialised context with no listener, created once and
// never destroyed, so lws never runs that global teardown. Every real
// listener/client context can then be destroyed and recreated safely (also
// confirmed by the probe: create/destroy/create/destroy, parsing still works).
// It holds no certificates, so it works even before certs/ exists.
// -----------------------------------------------------------------------------
namespace {
int LifetimeContextCallback(lws*, lws_callback_reasons, void*, void*, size_t) {
    return 0;
}
}  // namespace

static void EnsureTlsLifetimeContext() {
    static lws_context* lifetimeContext = nullptr;
    if (lifetimeContext != nullptr) {
        return;
    }
    static lws_protocols protocols[2] = {
        {"bacnet-sc-tls-lifetime", LifetimeContextCallback, 0, 0, 0, nullptr, 0},
        {nullptr, nullptr, 0, 0, 0, nullptr, 0}};
    lws_context_creation_info info;
    std::memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.gid = static_cast<gid_t>(-1);
    info.uid = static_cast<uid_t>(-1);
    lifetimeContext = lws_create_context(&info);  // deliberately never destroyed
    if (lifetimeContext == nullptr) {
        fprintf(stderr, "BACnet/SC: could not create the TLS lifetime context - a listener restart may crash\n");
    }
}

void ScTransport::Configure(const ScTlsFiles& tls, const std::string& acceptSubprotocol) {
    EnsureTlsLifetimeContext();
    m_tls = tls;
    m_acceptSubprotocol = acceptSubprotocol;
    // Set once, here, so both m_protocols[0].name (listener, built in
    // StartListening()) and m_clientProtocols[0].name (connector, built in
    // EnsureClientProtocolsTable()) point at the SAME backing storage - see
    // the header's comment on m_protocolNameStorage.
    m_protocolNameStorage = acceptSubprotocol;
    m_configured = true;
}

void ScTransport::SetConnectionRateLimits(const uint32_t perAddressPerSecond, const uint32_t totalPerSecond) {
    m_perAddressRateLimit = perAddressPerSecond;
    m_totalRateLimit = totalPerSecond;
    m_totalBucket = TokenBucket();  // starts full on first use
    m_addressBuckets.clear();
}

bool ScTransport::AllowNewConnectionAttempt(const std::string& address, const char** limitHit) {
    const auto now = std::chrono::steady_clock::now();

    if (m_perAddressRateLimit != 0) {
        auto it = m_addressBuckets.find(address);
        if (it == m_addressBuckets.end() && m_addressBuckets.size() >= kMaxTrackedAddresses) {
            // Age out every address whose bucket would be full again by now -
            // forgetting it loses nothing, since a new bucket starts full.
            const double idleSeconds = 1.0;
            for (auto a = m_addressBuckets.begin(); a != m_addressBuckets.end();) {
                if (std::chrono::duration<double>(now - a->second.lastRefill).count() >= idleSeconds) {
                    a = m_addressBuckets.erase(a);
                } else {
                    ++a;
                }
            }
        }
        if (it == m_addressBuckets.end() && m_addressBuckets.size() < kMaxTrackedAddresses) {
            it = m_addressBuckets.emplace(address, TokenBucket()).first;
        }
        // Still no room: every tracked address is busy right now. Fall back to
        // the total limit alone for this attempt rather than grow the table.
        if (it != m_addressBuckets.end() &&
            !TakeToken(&it->second.tokens, &it->second.lastRefill, m_perAddressRateLimit, now)) {
            *limitHit = "per-address";
            return false;
        }
    }

    if (m_totalRateLimit != 0 &&
        !TakeToken(&m_totalBucket.tokens, &m_totalBucket.lastRefill, m_totalRateLimit, now)) {
        *limitHit = "total";
        return false;
    }
    return true;
}

void ScTransport::LogListenFailureOnce(const std::string& reason) {
    if (m_loggedListenFailure) {
        return;
    }
    m_loggedListenFailure = true;
    fprintf(stderr, "BACnet/SC: %s\n", reason.c_str());
}

bool ScTransport::StartListening(const std::string& uri) {
    if (!m_configured) {
        LogListenFailureOnce("StartListening called before Configure()");
        return false;
    }
    if (m_listenerContext != nullptr) {
        if (m_listenUri == uri) {
            return true;  // already listening on exactly this URI
        }
        StopListening(m_listenUri);  // the accept URI changed - tear down and rebind
    }

    std::string host;
    uint16_t port = 0;
    if (!ParseWssUri(uri, &host, &port)) {
        LogListenFailureOnce("cannot start listening: \"" + uri + "\" is not a valid wss://host:port/... URI");
        return false;
    }

    {
        // Item 4: names specifically which file(s) failed, instead of
        // bundling cert/key/ca into one message regardless of which is
        // actually missing/unreadable - see DescribeMissingTlsFiles's own
        // comment.
        const std::string missing = DescribeMissingTlsFiles(m_tls);
        if (!missing.empty()) {
            LogListenFailureOnce(
                "cannot start listening on " + uri + ": certificate file(s) missing/unreadable: " +
                missing + ". Run: BACnetExampleBSCHUB --generate-certs");
            return false;
        }
    }
    // Item 3: startup certificate self-diagnosis - runs even though the files
    // above ARE readable (this diagnoses a file that exists but is WRONG -
    // expired, mismatched key, unparseable - not a replacement for the
    // missing-file check above). A confirmed cert/key mismatch skips this
    // attempt (lws_create_context could only fail); the next retry re-checks.
    if (!LogCertificateDiagnostics(m_tls)) {
        LogListenFailureOnce(
            "cannot start listening on " + uri + ": certificate/private key mismatch (see the "
            "\"DOES NOT MATCH\" line above). Fix the cert/key pair under --sc-cert-dir; the hub "
            "retries on its own.");
        return false;
    }

    // The protocol name string must outlive the context, so it lives on this
    // object (m_protocolNameStorage), not as a temporary. m_protocols itself
    // is heap-allocated (not a fixed array) so ScTransport.h does not need the
    // full `struct lws_protocols` definition - see the header's comment.
    //
    // 3 entries, not 2 (github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP#8):
    // a client that sends NO Sec-WebSocket-Protocol header gets protocols[0]
    // by lws's own default-protocol-index rule (lib/roles/ws/server-ws.c's
    // lws_process_ws_upgrade: an absent header binds
    // vhost->protocols[vhost->default_protocol_index], which defaults to 0,
    // regardless of that entry's name) and reaches LWS_CALLBACK_ESTABLISHED,
    // where SubprotocolListContains's re-check below sends a clean WS close
    // (1002) - correct, and unchanged by this fix.
    //
    // A client that NAMES a subprotocol lws doesn't have registered would be
    // dropped by lws_process_ws_upgrade ("No supported protocol") with no
    // response at all. HandleServerCallback's LWS_CALLBACK_HTTP_CONFIRM_UPGRADE
    // case answers that request with HTTP 400 first (issue #27), so a client
    // with a typo in its subprotocol gets a clear refusal instead.
    //
    // "dc.bsc.bacnet.org" (135-2020 AB.7.1's direct-connect subprotocol) is
    // registered as protocols[1] so it reaches ESTABLISHED, where it is closed
    // with its own reason ("direct-connect not supported by this hub") - it
    // is a valid BACnet/SC subprotocol this hub-only example doesn't
    // implement, not a client error.
    m_protocolNameStorage = m_acceptSubprotocol;
    delete[] m_protocols;
    m_protocols = new lws_protocols[3];
    std::memset(m_protocols, 0, sizeof(lws_protocols) * 3);
    m_protocols[0].name = m_protocolNameStorage.c_str();
    m_protocols[0].callback = &LwsServerCallbackTrampoline;
    m_protocols[0].per_session_data_size = 0;  // per-connection state lives in m_peers, keyed by wsi*
    m_protocols[0].rx_buffer_size = 4096;
    // A string literal, not m_protocolNameStorage-style heap storage - static
    // duration is sufficient since this exact spelling never changes at
    // runtime (unlike m_acceptSubprotocol, which SetConfig can vary).
    m_protocols[1].name = "dc.bsc.bacnet.org";
    m_protocols[1].callback = &LwsServerCallbackTrampoline;
    m_protocols[1].per_session_data_size = 0;
    m_protocols[1].rx_buffer_size = 4096;
    // m_protocols[2] stays all-zero - the required NULL-callback terminator.

    lws_context_creation_info info;
    std::memset(&info, 0, sizeof(info));
    info.port = port;
    info.iface = (host.empty() || host == "0.0.0.0") ? nullptr : host.c_str();
    info.protocols = m_protocols;
    info.ssl_cert_filepath = m_tls.certPath.c_str();
    info.ssl_private_key_filepath = m_tls.keyPath.c_str();
    info.ssl_ca_filepath = m_tls.caCertPath.c_str();
    // Mutual TLS (SC nodes/hubs authenticate each other by certificate, AB.5.3)
    // + TLS 1.3 only (135-2024 AB.5.2 mandates 1.3; SSL_OP_NO_TLSv1/1_1/1_2/SSLv3
    // disables every older negotiable version, leaving only 1.3).
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT | LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
    info.ssl_options_set = SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_SSLv3;
    info.user = this;
    info.gid = static_cast<gid_t>(-1);
    info.uid = static_cast<uid_t>(-1);

    // A failed create is retried, but not more often than kListenRetryInterval
    // (see the note above FileReadable()).
    const auto now = std::chrono::steady_clock::now();
    if (m_lastListenCreateFailure != std::chrono::steady_clock::time_point() &&
        now - m_lastListenCreateFailure < kListenRetryInterval) {
        return false;
    }

    lws_context* ctx = lws_create_context(&info);
    if (ctx == nullptr) {
        m_lastListenCreateFailure = now;
        LogListenFailureOnce("lws_create_context failed for " + uri + " (port " + std::to_string(port) +
                              " already in use? cert files malformed?) - retrying every " +
                              std::to_string(kListenRetryInterval.count()) + " s");
        return false;
    }

    m_listenerContext = ctx;
    m_listenUri = uri;
    m_nextClientId = 1;
    m_loggedListenFailure = false;
    m_lastListenCreateFailure = std::chrono::steady_clock::time_point();
    printf("BACnet/SC: listening for WebSocket/TLS connections on %s (subprotocol \"%s\", TLS 1.3, mutual auth)\n",
           uri.c_str(), m_acceptSubprotocol.c_str());
    return true;
}

void ScTransport::DestroyListenerContext() {
    if (m_listenerContext == nullptr) {
        return;
    }
    // lws_context_destroy synchronously closes every live wsi, which re-enters
    // HandleServerCallback with LWS_CALLBACK_CLOSED for each accepted peer
    // still in m_peers (queuing a Disconnected status event per peer - see the
    // CLOSED case below). That is harmless here: StopListening() is only ever
    // called because the STACK already decided to stop the hub function (it
    // has already forgotten these peers itself - see
    // BACnetDataLinkSC::SuspendCommunication in the stack source), so a later
    // DrainStatusEvents() call reporting Disconnected for an already-forgotten
    // peer is the documented "not logged as an error" no-op case (plan,
    // ScTransportRouter subsection).
    lws_context_destroy(m_listenerContext);
    m_listenerContext = nullptr;
    m_listenUri.clear();
    m_peers.clear();
    m_connStringToWsi.clear();
    delete[] m_protocols;
    m_protocols = nullptr;
}

void ScTransport::StopListening(const std::string& uri) {
    if (m_listenerContext == nullptr || m_listenUri != uri) {
        return;  // not listening on this URI - nothing to do
    }
    printf("BACnet/SC: no longer listening on %s\n", uri.c_str());
    DestroyListenerContext();
}

void ScTransport::ReloadCredentials() {
    if (m_listenerContext != nullptr) {
        const std::string uri = m_listenUri;
        printf("BACnet/SC: reloading certificates - restarting the listener on %s\n", uri.c_str());
        DestroyListenerContext();  // queues a Disconnected event per accepted peer
        if (!StartListening(uri)) {
            printf("BACnet/SC: could not restart the listener on %s with the new certificates\n", uri.c_str());
        }
    }
    for (auto& kv : m_clients) {
        if (kv.second.wsi != nullptr) {
            printf("BACnet/SC: reloading certificates - closing hub connection %s (the stack re-dials it)\n",
                   kv.first.c_str());
            Disconnect(kv.first);
        }
    }
}

bool ScTransport::IsListening() const {
    return m_listenerContext != nullptr;
}

void ScTransport::EnsureClientProtocolsTable() {
    if (m_clientProtocols != nullptr) {
        return;
    }
    // Shared by every ClientConnection's context - see the header comment.
    // Uses m_protocolNameStorage, the SAME backing string Configure() set for
    // the listener's table, so both halves always offer the identical
    // subprotocol name.
    m_clientProtocols = new lws_protocols[2];
    std::memset(m_clientProtocols, 0, sizeof(lws_protocols) * 2);
    m_clientProtocols[0].name = m_protocolNameStorage.c_str();
    m_clientProtocols[0].callback = &LwsClientCallbackTrampoline;
    m_clientProtocols[0].per_session_data_size = 0;  // per-connection state lives in ClientConnection, reached via lws_get_opaque_user_data
    m_clientProtocols[0].rx_buffer_size = 4096;
    // m_clientProtocols[1] stays all-zero - the required NULL-callback terminator.
}

void ScTransport::DestroyClientContext(ClientConnection& conn) {
    if (conn.context != nullptr) {
        // Synchronously closes the wsi if still open, re-entering
        // HandleClientCallback with LWS_CALLBACK_CLIENT_CLOSED - harmless
        // here for the same reason DestroyListenerContext's identical note
        // gives (a status event for a connection this method's OWN caller is
        // already tearing down is not useful, but queuing it costs nothing).
        lws_context_destroy(conn.context);
        conn.context = nullptr;
    }
    conn.wsi = nullptr;
}

bool ScTransport::Connect(const std::string& uri) {
    if (!m_configured) {
        fprintf(stderr, "BACnet/SC: Connect(\"%s\") requested before Configure()\n", uri.c_str());
        return false;
    }
    {
        // Item 4 - same per-file naming as StartListening() above.
        const std::string missing = DescribeMissingTlsFiles(m_tls);
        if (!missing.empty()) {
            fprintf(stderr,
                    "BACnet/SC: cannot Connect(\"%s\"): certificate file(s) missing/unreadable: %s. "
                    "Run: BACnetExampleBSCHUB --generate-certs\n",
                    uri.c_str(), missing.c_str());
            return false;
        }
    }
    // Item 3 - same startup self-diagnosis as StartListening() above; the
    // connector presents the SAME identity cert (this device has one identity
    // regardless of role - see the class header comment), so it is worth
    // diagnosing here too, not only for the listener. A confirmed mismatch
    // skips this attempt; the stack's reconnect timer calls Connect() again.
    if (!LogCertificateDiagnostics(m_tls)) {
        fprintf(stderr,
                "BACnet/SC: cannot Connect(\"%s\"): certificate/private key mismatch (see the "
                "\"DOES NOT MATCH\" line above). Fix the cert/key pair under --sc-cert-dir.\n",
                uri.c_str());
        return false;
    }

    std::string host;
    std::string path;
    uint16_t port = 0;
    if (!ParseWssUri(uri, &host, &port, &path) || host.empty()) {
        // Unlike the listener, an empty/omitted host is NOT valid here - a
        // connector must dial a specific hub, never "0.0.0.0" (that is a bind
        // address, meaningless as a dial target).
        fprintf(stderr, "BACnet/SC: cannot Connect(): \"%s\" is not a valid wss://host:port/path URI\n",
                uri.c_str());
        return false;
    }

    // A fresh dial every time Connect() is called for this URI - tear down
    // any stale context first (a previous attempt that already closed/errored;
    // per plan fact 7 this class itself never re-dials, so reaching this line
    // again for the same URI only ever happens because the CALLER - ultimately
    // the stack's own retry/reconnect timer - asked for it again).
    auto existing = m_clients.find(uri);
    if (existing != m_clients.end()) {
        DestroyClientContext(existing->second);
        m_clients.erase(existing);
    }

    EnsureClientProtocolsTable();

    // std::map<std::string, ClientConnection>::operator[] gives a reference
    // that stays valid across later inserts/erases of OTHER keys (see the
    // header's comment on m_clients) - safe to hand its address to lws as
    // opaque_user_data below and keep using it after this call returns.
    ClientConnection& conn = m_clients[uri];
    conn.uri = uri;

    lws_context_creation_info info;
    std::memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;  // connector role only - this context is never a server
    info.protocols = m_clientProtocols;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.client_ssl_ca_filepath = m_tls.caCertPath.c_str();          // validates the HUB's certificate
    info.client_ssl_cert_filepath = m_tls.certPath.c_str();          // this device's own operational cert (mutual TLS)
    info.client_ssl_private_key_filepath = m_tls.keyPath.c_str();
    // TLS 1.3 only, same restriction as the listener half (135-2024 AB.5.2).
    info.ssl_client_options_set = SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_SSLv3;
    info.user = this;
    info.gid = static_cast<gid_t>(-1);
    info.uid = static_cast<uid_t>(-1);

    lws_context* ctx = lws_create_context(&info);
    if (ctx == nullptr) {
        fprintf(stderr, "BACnet/SC: Connect(\"%s\"): lws_create_context failed\n", uri.c_str());
        m_clients.erase(uri);
        return false;
    }
    conn.context = ctx;

    lws_client_connect_info ccinfo;
    std::memset(&ccinfo, 0, sizeof(ccinfo));
    ccinfo.context = ctx;
    ccinfo.address = host.c_str();
    ccinfo.port = port;
    ccinfo.path = path.c_str();
    ccinfo.host = host.c_str();
    ccinfo.origin = host.c_str();
    ccinfo.protocol = m_acceptSubprotocol.c_str();  // "hub.bsc.bacnet.org" - plan fact 1, NOT plugfest-example's wrong "hub.bacnet.org"
    // LCCSCF_USE_SSL: TLS on. LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK: the CA
    // chain is STILL fully verified (client_ssl_ca_filepath above requires a
    // valid chain to m_tls.caCertPath) - only the hostname-in-certificate
    // check is skipped. BACnet/SC certificates identify a DEVICE (by its
    // UUID/VMAC-derived identity, 135-2024 AB.1.5.3), not a DNS hostname the
    // way an ordinary HTTPS server certificate does, so requiring the SAN to
    // list "127.0.0.1"/the hub's hostname would reject a conformant BACnet/SC
    // hub whose certificate (correctly) does not encode that - see the plan's
    // Connector subsection and open risk #6 (this app's cert policy is
    // CA-chain-only; there is no hostname or UUID-in-SAN binding here).
    ccinfo.ssl_connection = LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
    ccinfo.opaque_user_data = &conn;
    lws* wsi = nullptr;
    ccinfo.pwsi = &wsi;

    if (lws_client_connect_via_info(&ccinfo) == nullptr) {
        // A hard, immediate failure (bad address, etc.) - note lws may ALSO
        // have already called HandleClientCallback synchronously with
        // LWS_CALLBACK_CLIENT_CONNECTION_ERROR for this same attempt (plan
        // fact 6); that queues its own Error(4) status event, which is fine -
        // an extra queued event for a connection we are about to erase here
        // is harmless (DrainStatusEvents' "not accepted" case, main.cpp).
        fprintf(stderr, "BACnet/SC: Connect(\"%s\"): lws_client_connect_via_info failed immediately\n",
                uri.c_str());
        lws_context_destroy(ctx);
        m_clients.erase(uri);
        return false;
    }
    conn.wsi = wsi;
    printf("BACnet/SC: dialing out to %s (subprotocol \"%s\", TLS 1.3, mutual auth)\n",
           uri.c_str(), m_acceptSubprotocol.c_str());
    return true;
}

void ScTransport::Disconnect(const std::string& connStr) {
    // Case 1: an accepted server peer ("<acceptUri>|client=N", Phase 2 half).
    auto serverIt = m_connStringToWsi.find(connStr);
    if (serverIt != m_connStringToWsi.end()) {
        PeerConnection* peer = FindPeerByWsi(serverIt->second);
        if (peer != nullptr) {
            RequestClose(peer->wsi, &peer->closeRequest, LWS_CLOSE_STATUS_NORMAL, std::string());
        }
        return;
    }
    // Case 2: an outbound connector URI (this phase).
    auto clientIt = m_clients.find(connStr);
    if (clientIt != m_clients.end() && clientIt->second.wsi != nullptr) {
        RequestClose(clientIt->second.wsi, &clientIt->second.closeRequest, LWS_CLOSE_STATUS_NORMAL, std::string());
        return;
    }
    // Unknown/already-closed connString - no-op, matching the header's contract.
}

void ScTransport::RequestClose(lws* wsi, CloseRequest* closeRequest, const uint16_t code, const std::string& reason) {
    if (closeRequest->requested) {
        return;
    }
    closeRequest->requested = true;
    closeRequest->code = code;
    closeRequest->reason = reason;
    lws_callback_on_writable(wsi);  // the close itself happens in the WRITEABLE callback
}

bool ScTransport::ApplyRequestedClose(lws* wsi, const CloseRequest& closeRequest) {
    if (!closeRequest.requested) {
        return false;
    }
    lws_close_reason(wsi, static_cast<lws_close_status>(closeRequest.code),
                     reinterpret_cast<unsigned char*>(const_cast<char*>(closeRequest.reason.data())),
                     closeRequest.reason.size());
    return true;
}

bool ScTransport::EnqueueFrame(lws* wsi, std::deque<std::vector<uint8_t>>* txQueue, CloseRequest* closeRequest,
                               const std::string& label, const uint8_t* data, const uint16_t len) {
    if (closeRequest->requested) {
        return false;  // already closing - nothing more goes out on this connection
    }
    if (txQueue->size() >= kMaxTxQueueFrames) {
        // The peer has stopped reading (issue #16). Give up on it rather than
        // buffer without limit; its close is reported to the stack like any other.
        ++m_txQueueOverflows;
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "SC transmit queue full: %zu frames waiting for %s - closing the connection (1008)",
            txQueue->size(), label.c_str());
        txQueue->clear();
        RequestClose(wsi, closeRequest, LWS_CLOSE_STATUS_POLICY_VIOLATION, "transmit queue full");
        return false;
    }
    std::vector<uint8_t> framed(static_cast<std::size_t>(LWS_PRE) + len);
    if (len > 0) {
        std::memcpy(framed.data() + LWS_PRE, data, len);
    }
    txQueue->push_back(std::move(framed));
    lws_callback_on_writable(wsi);
    return true;
}

ScTransport::PeerConnection* ScTransport::FindPeerByWsi(lws* wsi) {
    auto it = m_peers.find(wsi);
    return (it == m_peers.end()) ? nullptr : &it->second;
}

bool ScTransport::Send(const std::string& connStr, const uint8_t* data, uint16_t len) {
    // Case 1: an accepted server peer ("<acceptUri>|client=N", Phase 2 half).
    auto serverIt = m_connStringToWsi.find(connStr);
    if (serverIt != m_connStringToWsi.end()) {
        PeerConnection* peer = FindPeerByWsi(serverIt->second);
        if (peer == nullptr) {
            return false;
        }
        AuditSentFrame(peer, data, len);
        return EnqueueFrame(peer->wsi, &peer->txQueue, &peer->closeRequest,
                            "\"" + peer->connectionString + "\" (" + peer->peerAddress + ")", data, len);
    }

    // Case 2: an outbound connector connection, keyed by the URI Connect()
    // was called with. A connString that names a connector entry whose
    // wsi is currently null (never established, or already closed) is
    // treated as unknown - matching the header's "unknown/closed" contract.
    auto clientIt = m_clients.find(connStr);
    if (clientIt != m_clients.end() && clientIt->second.wsi != nullptr) {
        ClientConnection& conn = clientIt->second;
        return EnqueueFrame(conn.wsi, &conn.txQueue, &conn.closeRequest, "hub \"" + conn.uri + "\"", data, len);
    }

    return false;  // unknown/closed peer - caller (the router) returns 0 to the stack
}

void ScTransport::Service() {
    // Phase 1 spike mechanism (a) - see docs/bacnet-sc-transport-plan.md and
    // the class header comment. Confirmed non-blocking on Windows.
    if (m_listenerContext != nullptr) {
        lws_cancel_service(m_listenerContext);
        lws_service(m_listenerContext, 0);
    }
    // One client lws_context per connector connection (plan's Connector
    // subsection) - pump every live one the same non-blocking way.
    for (auto& kv : m_clients) {
        if (kv.second.context != nullptr) {
            lws_cancel_service(kv.second.context);
            lws_service(kv.second.context, 0);
        }
    }
}

bool ScTransport::PopReceived(ScReceivedFrame* outFrame) {
    if (m_rxQueue.empty() || outFrame == nullptr) {
        return false;
    }
    *outFrame = std::move(m_rxQueue.front());
    m_rxQueue.pop_front();
    return true;
}

ScTransportMetrics ScTransport::GetMetrics() const {
    ScTransportMetrics m;
    m.totalConnects = m_totalConnects;
    m.totalDisconnects = m_totalDisconnects;
    m.rateLimitRejections = m_rateLimitRejections;
    m.rxMessages = m_rxMessages;
    m.rxBytes = m_rxBytes;
    m.txMessages = m_txMessages;
    m.txBytes = m_txBytes;
    m.txQueueOverflows = m_txQueueOverflows;
    m.currentPeerCount = m_peers.size();
    return m;
}

std::vector<ScPeerInfo> ScTransport::GetPeers() const {
    std::map<uint64_t, ScPeerInfo> byId;  // oldest connection first
    for (const auto& kv : m_peers) {
        const PeerConnection& peer = kv.second;
        ScPeerInfo info;
        info.connectionString = peer.connectionString;
        info.address = peer.peerAddress;
        info.certificateSubject = peer.certificateSubject;
        info.vmac = peer.vmac;
        info.uuid = peer.uuid;
        info.accepted = peer.accepted;
        byId[peer.clientId] = info;
    }
    std::vector<ScPeerInfo> peers;
    for (const auto& kv : byId) {
        peers.push_back(kv.second);
    }
    return peers;
}

void ScTransport::AuditReceivedFrame(PeerConnection* peer, const std::vector<uint8_t>& frame) {
    if (frame.empty() || frame[0] != kBvlcConnectRequest) {
        return;
    }
    const std::size_t offset = BvlcPayloadOffset(frame.data(), frame.size());
    if (offset == 0 || frame.size() < offset + 6 + 16) {
        return;  // malformed - the stack will refuse it; nothing to record
    }
    peer->vmac = HexBytes(&frame[offset], 6, ":");
    peer->uuid = FormatUuid(&frame[offset + 6]);
}

void ScTransport::AuditSentFrame(PeerConnection* peer, const uint8_t* data, const uint16_t len) {
    if (len == 0 || peer->accepted || peer->uuid.empty()) {
        return;  // only the answer to a recorded Connect-Request is of interest
    }
    if (data[0] == kBvlcConnectAccept) {
        peer->accepted = true;
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
            "SC audit: peer \"%s\" (%s) is BACnet/SC device VMAC %s, UUID %s, certificate \"%s\" - connected",
            peer->connectionString.c_str(), peer->peerAddress.c_str(), peer->vmac.c_str(), peer->uuid.c_str(),
            peer->certificateSubject.c_str());
    } else if (data[0] == kBvlcResult) {
        // A BVLC-Result to a peer that hasn't been accepted is the stack
        // refusing its Connect-Request. The NAK carries the stack's reason
        // (135-2024 AB.2.4: result-for-function, result code 0x01, then error
        // header marker, error class and error code - 2 octets each - and
        // UTF-8 error details), so log that rather than guess (issue #40).
        std::string reason = "no reason given";
        const std::size_t offset = BvlcPayloadOffset(data, len);
        if (offset != 0 && len >= offset + 7 && data[offset + 1] == 0x01) {
            const unsigned errorClass = (static_cast<unsigned>(data[offset + 3]) << 8) | data[offset + 4];
            const unsigned errorCode = (static_cast<unsigned>(data[offset + 5]) << 8) | data[offset + 6];
            const std::string details(reinterpret_cast<const char*>(data) + offset + 7, len - (offset + 7));
            reason = (details.empty() ? std::string("no details") : "\"" + details + "\"") +
                     ", error class " + std::to_string(errorClass) + " code " + std::to_string(errorCode);
        }
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "SC audit: peer \"%s\" (%s) - BACnet/SC device VMAC %s, UUID %s, certificate \"%s\" - "
            "Connect-Request refused by the hub: %s",
            peer->connectionString.c_str(), peer->peerAddress.c_str(), peer->vmac.c_str(), peer->uuid.c_str(),
            peer->certificateSubject.c_str(), reason.c_str());
    }
}

bool ScTransport::PopStatusEvent(ScStatusEvent* outEvent) {
    if (m_statusQueue.empty() || outEvent == nullptr) {
        return false;
    }
    *outEvent = m_statusQueue.front();
    m_statusQueue.pop_front();
    return true;
}

bool ScTransport::FlushOneQueuedFrame(lws* wsi, std::deque<std::vector<uint8_t>>* txQueue, const std::string& label) {
    if (txQueue->empty()) {
        return false;
    }
    std::vector<uint8_t>& framed = txQueue->front();
    const std::size_t payloadLen = framed.size() - static_cast<std::size_t>(LWS_PRE);
    const int written = lws_write(wsi, framed.data() + LWS_PRE, payloadLen, LWS_WRITE_BINARY);
    txQueue->pop_front();
    if (written < 0 || static_cast<std::size_t>(written) < payloadLen) {
        // `label` is the fully-formatted "who" clause (e.g. "\"<connStr>\""
        // for the server half, "hub \"<uri>\"" for the client half) - kept
        // as each caller's own literal wording, not rebuilt here, so this
        // shared helper doesn't have to know which half it's serving.
        fprintf(stderr, "BACnet/SC: short/failed write to %s (%d of %zu bytes) - closing\n",
                label.c_str(), written, payloadLen);
        return true;
    }
    ++m_txMessages;
    m_txBytes += static_cast<uint64_t>(payloadLen);
    if (!txQueue->empty()) {
        lws_callback_on_writable(wsi);  // more frames queued - ask for another turn
    }
    return false;
}

int ScTransport::HandleServerCallback(lws* wsi, int reasonInt, void* user, void* in, std::size_t len) {
    const lws_callback_reasons reason = static_cast<lws_callback_reasons>(reasonInt);

    switch (reason) {
        case LWS_CALLBACK_FILTER_NETWORK_CONNECTION: {
            // Fires at raw-socket accept() time, BEFORE TLS negotiation and
            // before any BACnet/SC-specific state exists for this connection
            // (lws's own doc comment: "wsi still pointing to the main server
            // socket" - there is no PeerConnection/connection string yet, and
            // won't be one if this rejects). This is the earliest, cheapest
            // point this transport can gate a flood of connection attempts -
            // see ScTransport::SetConnectionRateLimits' header
            // comment for why this is a separate control from
            // sc-max-hub-connections. Returning non-zero here makes lws hang
            // up immediately, before sending or receiving anything - no TLS
            // handshake CPU/memory is spent on a rejected attempt.
            // `user` is lws's struct lws_filter_network_conn_args here - the
            // only place the new peer's address is available this early (wsi
            // is still the listening socket; see PeerAddressPort()).
            const lws_filter_network_conn_args* args = static_cast<const lws_filter_network_conn_args*>(user);
            const std::string address = (args != nullptr) ? AddressFromSockaddr(args->cli_addr) : std::string("?");
            const char* limitHit = "";
            if (!AllowNewConnectionAttempt(address, &limitHit)) {
                ++m_rateLimitRejections;
                CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                    "SC rate limit: refusing a new connection from %s on %s - %s limit of %u attempt(s)/sec "
                    "reached (refused before the TLS handshake; see --sc-rate-limit%s)",
                    address.c_str(), m_listenUri.c_str(), limitHit,
                    (unsigned)(std::strcmp(limitHit, "total") == 0 ? m_totalRateLimit : m_perAddressRateLimit),
                    std::strcmp(limitHit, "total") == 0 ? "-total" : "");
                return -1;
            }
            break;
        }

        case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
            // The listener's SSL_CTX (in `user`), as lws creates it - load the
            // CRL (issue #15). Non-zero fails the context: fail closed.
            return LoadRevocationList(static_cast<SSL_CTX*>(user), m_tls.crlPath, "listener") ? 0 : 1;

        case LWS_CALLBACK_HTTP_CONFIRM_UPGRADE: {
            // The WebSocket upgrade request has arrived but lws hasn't matched
            // its subprotocol yet (lws 4.5.8 lib/roles/http/server/server.c).
            // An unknown subprotocol would make lws drop the TCP connection
            // without a response (issue #27), so refuse it here with a real
            // HTTP 400 instead. Returning 1 tells lws we sent the response.
            // No subprotocol at all, ours, or dc.bsc.bacnet.org carry on to
            // ESTABLISHED, which closes the last two cases with a WebSocket
            // close frame and a reason.
            char requested[256] = {0};
            lws_hdr_copy(wsi, requested, static_cast<int>(sizeof(requested)), WSI_TOKEN_PROTOCOL);
            if (requested[0] != '\0' && !SubprotocolListContains(requested, m_acceptSubprotocol) &&
                !SubprotocolListContains(requested, "dc.bsc.bacnet.org")) {
                const std::string peerAddress = PeerAddressPort(wsi);
                CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                    "BACnet/SC: refusing a WebSocket upgrade from %s - it asked for subprotocol(s) \"%s\", "
                    "this hub speaks \"%s\" (HTTP 400)", peerAddress.c_str(), requested, m_acceptSubprotocol.c_str());
                // Written by hand rather than with lws_return_http_status(): at
                // this point lws hasn't recorded the request's HTTP version, so
                // that helper answers "HTTP/1.0", which WebSocket clients
                // (RFC 6455 needs HTTP/1.1) reject as an invalid response.
                const std::string body = "unsupported WebSocket subprotocol; this BACnet/SC hub accepts \"" +
                                         m_acceptSubprotocol + "\"\n";
                const std::string response = "HTTP/1.1 400 Bad Request\r\ncontent-type: text/plain\r\n"
                                             "content-length: " + std::to_string(body.size()) +
                                             "\r\nconnection: close\r\n\r\n" + body;
                std::vector<unsigned char> buffer(static_cast<std::size_t>(LWS_PRE) + response.size());
                std::memcpy(buffer.data() + LWS_PRE, response.data(), response.size());
                if (lws_write(wsi, buffer.data() + LWS_PRE, response.size(), LWS_WRITE_HTTP_HEADERS) < 0) {
                    return -1;
                }
                return 1;  // we answered; lws completes (and closes) the transaction
            }
            break;
        }

        case LWS_CALLBACK_ESTABLISHED: {
            // Verify the client actually asked for our subprotocol ourselves -
            // see SubprotocolListContains's comment for why this is not left to
            // lws's own negotiation. This callback only fires for a request
            // lws itself already bound to one of THIS transport's registered
            // protocols (no subprotocol requested at all, "hub.bsc.bacnet.org"
            // itself, or the explicitly-registered "dc.bsc.bacnet.org" - see
            // m_protocols[1]'s comment in StartListening()); an unrecognised
            // subprotocol name was already refused with HTTP 400 at
            // LWS_CALLBACK_HTTP_CONFIRM_UPGRADE above.
            char requested[256] = {0};
            lws_hdr_copy(wsi, requested, static_cast<int>(sizeof(requested)), WSI_TOKEN_PROTOCOL);
            if (!SubprotocolListContains(requested, m_acceptSubprotocol)) {
                // "dc.bsc.bacnet.org" (135-2020 AB.7.1, BACnet/SC direct
                // connect) is a real BACnet/SC subprotocol this hub-function-
                // only build does not implement - not a client typo. Naming
                // that distinction in the close reason (#8's own suggestion)
                // saves a partner from mistaking "not implemented" for "you
                // asked for something malformed."
                const bool isDirectConnect = SubprotocolListContains(requested, "dc.bsc.bacnet.org");
                const char* const closeReason = isDirectConnect
                    ? "direct-connect (dc.bsc.bacnet.org) not supported by this hub"
                    : "unsupported subprotocol";
                fprintf(stderr, "BACnet/SC: rejecting connection - client asked for subprotocol(s) "
                                "\"%s\", not \"%s\"\n", requested, m_acceptSubprotocol.c_str());
                lws_close_reason(wsi, LWS_CLOSE_STATUS_PROTOCOL_ERR,
                                 (unsigned char*)closeReason, static_cast<unsigned int>(strlen(closeReason)));
                return -1;
            }

            // Mint the accepted-peer connection string (plan fact 2, verified
            // against BACnetDataLinkSC::DoesConfiguredUriMatch): "<acceptUri>|client=<N>".
            const uint64_t clientId = m_nextClientId++;
            const std::string connStr = m_listenUri + "|client=" + std::to_string(clientId);
            PeerConnection& peer = m_peers[wsi];
            peer.wsi = wsi;
            peer.clientId = clientId;
            peer.connectionString = connStr;
            peer.peerAddress = PeerAddressPort(wsi);  // captured once here, reused at CLOSED below
            peer.certificateSubject = PeerCertificateSubject(wsi);
            m_connStringToWsi[connStr] = wsi;
            ++m_totalConnects;
            printf("BACnet/SC: accepted WebSocket connection - peer=\"%s\" from %s\n",
                   connStr.c_str(), peer.peerAddress.c_str());
            // Audit trail (issue #21). The connection string only means "the
            // Nth socket this run", so the audit line also names the TLS
            // certificate the peer presented. Its BACnet/SC identity - VMAC
            // and device UUID - arrives in its Connect-Request right after
            // this; AuditReceivedFrame()/AuditSentFrame() log it when the
            // stack accepts (or refuses) that request. CASExampleHelper::Log
            // prefixes every line with a UTC timestamp.
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                "SC audit: peer \"%s\" connected from %s, certificate \"%s\"", connStr.c_str(),
                peer.peerAddress.c_str(), peer.certificateSubject.c_str());
            // Deliberately NOT queuing a Connected(2) status event here - see
            // ScStatusEvent's doc comment and plan open risk #7: an accepted
            // socket is not yet a BACnet/SC "connection" until the stack's own
            // Connect-Request/Accept exchange (which arrives as ordinary RX
            // data, handled below) completes.
            break;
        }

        case LWS_CALLBACK_RECEIVE: {
            PeerConnection* peer = FindPeerByWsi(wsi);
            if (peer == nullptr) {
                break;
            }
            const uint64_t framesBefore = m_rxMessages;
            if (HandleIncomingFragment(wsi, in, len, peer->connectionString, m_listenUri,
                                       &peer->rxAssembly, &peer->rxOverflow)) {
                return -1;
            }
            if (m_rxMessages != framesBefore && !peer->accepted) {
                AuditReceivedFrame(peer, m_rxQueue.back().data);  // a complete frame - its Connect-Request?
            }
            break;
        }

        case LWS_CALLBACK_SERVER_WRITEABLE: {
            PeerConnection* peer = FindPeerByWsi(wsi);
            if (peer == nullptr) {
                break;
            }
            if (ApplyRequestedClose(wsi, peer->closeRequest)) {
                return -1;  // Disconnect() or a full transmit queue asked for this close
            }
            if (FlushOneQueuedFrame(wsi, &peer->txQueue, "\"" + peer->connectionString + "\"")) {
                return -1;
            }
            break;
        }

        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE: {
            PeerConnection* peer = FindPeerByWsi(wsi);
            if (peer != nullptr && in != nullptr && len >= 2) {
                const uint8_t* bytes = static_cast<const uint8_t*>(in);
                peer->lastCloseCode = static_cast<uint16_t>((bytes[0] << 8) | bytes[1]);
            }
            break;
        }

        case LWS_CALLBACK_CLOSED: {
            PeerConnection* peer = FindPeerByWsi(wsi);
            if (peer != nullptr) {
                // Plan fact 3 / open risk #7: a clean close (1000, or no close
                // frame at all - an abrupt drop) reports Disconnected(3);
                // anything else reports Error(4).
                const uint8_t status = (peer->lastCloseCode == 0 || peer->lastCloseCode == 1000)
                    ? 3 /* WebsocketStatus_Disconnected */
                    : 4 /* WebsocketStatus_Error */;
                ScStatusEvent evt;
                evt.uri = peer->connectionString;
                evt.status = status;
                evt.closeCode = peer->lastCloseCode;
                m_statusQueue.push_back(evt);
                ++m_totalDisconnects;
                printf("BACnet/SC: peer \"%s\" (%s) disconnected (status=%u closeCode=%u)\n",
                       peer->connectionString.c_str(), peer->peerAddress.c_str(), (unsigned)status,
                       (unsigned)peer->lastCloseCode);
                // Audit trail (Task 1) - same identity/timestamp rationale as
                // the "connected" line above. Item 2: reuses the peerAddress
                // captured once at ESTABLISHED (see PeerConnection::peerAddress's
                // own comment) rather than re-querying lws here - by CLOSED the
                // underlying socket may already be torn down.
                CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                    "SC audit: peer \"%s\" (%s) disconnected (closeCode=%u) - BACnet/SC device VMAC %s, "
                    "UUID %s, certificate \"%s\"",
                    peer->connectionString.c_str(), peer->peerAddress.c_str(), (unsigned)peer->lastCloseCode,
                    peer->vmac.empty() ? "?" : peer->vmac.c_str(), peer->uuid.empty() ? "?" : peer->uuid.c_str(),
                    peer->certificateSubject.c_str());
                m_connStringToWsi.erase(peer->connectionString);
                m_peers.erase(wsi);
            }
            break;
        }

        default:
            break;
    }
    return 0;
}

bool ScTransport::HandleIncomingFragment(lws* wsi, const void* in, std::size_t len,
                                         const std::string& sourceConnStr, const std::string& destConnStr,
                                         std::vector<uint8_t>* rxAssembly, bool* rxOverflow) {
    if (!lws_frame_is_binary(wsi)) {
        // BACnet/SC is binary-framed only (135-2024 AB.7.4). Reject a text
        // frame with 1003 (plan/V1 negative case) - shared by both roles.
        fprintf(stderr, "BACnet/SC: peer \"%s\" sent a non-binary frame - closing (1003)\n",
                sourceConnStr.c_str());
        lws_close_reason(wsi, LWS_CLOSE_STATUS_UNACCEPTABLE_OPCODE, (unsigned char*)"binary only", 11);
        return true;
    }

    const uint8_t* bytes = static_cast<const uint8_t*>(in);
    if (!*rxOverflow) {
        if (rxAssembly->size() + len > kMaxIngressBytes) {
            // Plan fact 8: BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH is 1600
            // bytes (post cas-bacnet-stack#2225 fix) - a bigger frame is
            // discarded and logged, never handed to the stack.
            *rxOverflow = true;
            rxAssembly->clear();
            fprintf(stderr, "BACnet/SC: discarding oversized frame (> %zu bytes) from \"%s\" - "
                            "ingress ceiling (BACNET_INTERFACE_MAX_INPUT_BUFFER_LENGTH)\n",
                    kMaxIngressBytes, sourceConnStr.c_str());
        } else if (len > 0) {
            rxAssembly->insert(rxAssembly->end(), bytes, bytes + len);
        }
    }

    if (lws_is_final_fragment(wsi)) {
        if (!*rxOverflow) {
            ScReceivedFrame frame;
            frame.sourceConnectionString = sourceConnStr;
            frame.destinationConnectionString = destConnStr;
            frame.data = *rxAssembly;
            ++m_rxMessages;
            m_rxBytes += static_cast<uint64_t>(frame.data.size());
            m_rxQueue.push_back(std::move(frame));
        }
        rxAssembly->clear();
        *rxOverflow = false;
    }
    return false;
}

int ScTransport::HandleClientCallback(lws* wsi, int reasonInt, void* user, void* in, std::size_t len) {
    const lws_callback_reasons reason = static_cast<lws_callback_reasons>(reasonInt);
    if (reason == LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS) {
        // The connector's SSL_CTX (in `user`), as lws creates it, on a fake
        // wsi with only the context set - so handled before the per-connection
        // lookup below. Load the CRL so the hub we dial is checked too.
        LoadRevocationList(static_cast<SSL_CTX*>(user), m_tls.crlPath, "connector");
        return 0;
    }
    // Every reason below fires on a wsi lws created from THIS connection's own
    // Connect() call, which set ccinfo.opaque_user_data = &conn (a stable
    // reference into m_clients - see the header's comment on that map) - so
    // this lookup is valid for every case, including one that fires
    // synchronously from inside Connect() itself (plan fact 6).
    ClientConnection* conn = static_cast<ClientConnection*>(lws_get_opaque_user_data(wsi));

    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            if (conn == nullptr) {
                break;
            }
            conn->wsi = wsi;
            // Item 2 (lower priority for the connector half - it already
            // knows what URI it dialed; this adds the actual resolved
            // remote address/port, useful when the URI names a hostname
            // rather than a bare IP, or when failover has multiple A
            // records).
            conn->peerAddress = PeerAddressPort(wsi);
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Info,
                "SC audit: connected to hub \"%s\" (%s), certificate \"%s\"", conn->uri.c_str(),
                conn->peerAddress.c_str(), PeerCertificateSubject(wsi).c_str());
            ScStatusEvent evt;
            evt.uri = conn->uri;
            evt.status = 2;  // WebsocketStatus_Connected (plan fact 3)
            evt.closeCode = 0;
            m_statusQueue.push_back(evt);
            if (!conn->txQueue.empty()) {
                lws_callback_on_writable(wsi);  // a Send() may have queued before ESTABLISHED fired
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            if (conn == nullptr) {
                break;
            }
            const std::string detail = (in != nullptr) ? std::string(static_cast<const char*>(in), len) : std::string();
            // Item 2: best-effort only - a connection error can fire before
            // the socket is far enough along for lws_get_peer_simple()/
            // getpeername() to know anything (e.g. a DNS failure), in which
            // case PeerAddressPort() honestly reports "?:?" rather than
            // fabricating an address.
            const std::string peerAddr = (wsi != nullptr) ? PeerAddressPort(wsi) : std::string("?:?");
            fprintf(stderr, "BACnet/SC: Connect(\"%s\") failed (peer %s): %s\n", conn->uri.c_str(),
                    peerAddr.c_str(), detail.c_str());
            ScStatusEvent evt;
            evt.uri = conn->uri;
            evt.status = 4;  // WebsocketStatus_Error (plan fact 3)
            evt.closeCode = 0;
            m_statusQueue.push_back(evt);
            conn->wsi = nullptr;
            break;
        }

        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE: {
            // Same generic (non-CLIENT_-prefixed) reason the listener half
            // uses - fires for a client-role wsi too. Recorded only for the
            // log line below; unlike the listener half, this class does not
            // branch Disconnected-vs-Error on it for the connector (see
            // ScStatusEvent's header comment).
            if (conn != nullptr && in != nullptr && len >= 2) {
                const uint8_t* bytes = static_cast<const uint8_t*>(in);
                conn->lastCloseCode = static_cast<uint16_t>((bytes[0] << 8) | bytes[1]);
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {
            if (conn == nullptr) {
                break;
            }
            // destConnStr is empty for a connector-side frame - see
            // ScReceivedFrame's header comment ("empty (connector)").
            if (HandleIncomingFragment(wsi, in, len, conn->uri, std::string(),
                                       &conn->rxAssembly, &conn->rxOverflow)) {
                return -1;
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            if (conn == nullptr) {
                break;
            }
            if (ApplyRequestedClose(wsi, conn->closeRequest)) {
                return -1;
            }
            if (FlushOneQueuedFrame(wsi, &conn->txQueue, "hub \"" + conn->uri + "\"")) {
                return -1;
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_CLOSED: {
            if (conn == nullptr) {
                break;
            }
            // Plan spec for the connector half: EVERY close (clean or not)
            // reports Disconnected(3) here - LWS_CALLBACK_CLIENT_CONNECTION_ERROR
            // above is the only path that reports Error(4) for this half (unlike
            // the listener half's closeCode-based split - see ScStatusEvent's
            // header comment).
            ScStatusEvent evt;
            evt.uri = conn->uri;
            evt.status = 3;  // WebsocketStatus_Disconnected (plan fact 3)
            evt.closeCode = conn->lastCloseCode;
            m_statusQueue.push_back(evt);
            // Item 2: reuses the address captured at CLIENT_ESTABLISHED
            // (conn->peerAddress) - same "the socket may already be gone by
            // CLOSED" reasoning as the listener half's PeerConnection::peerAddress.
            printf("BACnet/SC: hub connection \"%s\" (%s) closed (closeCode=%u)\n",
                   conn->uri.c_str(), conn->peerAddress.c_str(), (unsigned)conn->lastCloseCode);
            conn->wsi = nullptr;
            break;
        }

        default:
            break;
    }
    return 0;
}

}  // namespace CASSc
