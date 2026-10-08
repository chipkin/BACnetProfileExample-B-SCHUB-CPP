// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
#ifndef CAS_SC_LOG_SAFE_H
#define CAS_SC_LOG_SAFE_H

// LogSafe.h
// =============================================================================
// SafeForLog(): text a PEER chose - a certificate's subject, a WebSocket
// subprotocol header, a NAK's error details, an HTTP path - made safe to put
// in a log line. Control characters (below 0x20, and 0x7f) are
// written as \xNN, so a certificate whose CN holds "\n2026-... [INFO] SC audit:
// ..." can't forge a log line, and escape sequences can't reach a terminal.
// Everything else, UTF-8 included, is kept. Long values are cut to maxBytes.
//
// It lives here rather than in CASExampleHelper::Log because common/ is shared
// by every example in the series and isn't edited in one repository alone.
// =============================================================================

#include <cstdio>
#include <string>

namespace CASSc {

inline std::string SafeForLog(const std::string& text, const std::size_t maxBytes = 512) {
    std::string out;
    out.reserve(text.size() < maxBytes ? text.size() : maxBytes);
    for (const char ch : text) {
        if (out.size() >= maxBytes) {
            out += "...";
            break;
        }
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c == 0x7f) {
            char escaped[5];
            std::snprintf(escaped, sizeof(escaped), "\\x%02x", c);
            out += escaped;
        } else {
            out += ch;
        }
    }
    return out;
}

}  // namespace CASSc

#endif  // CAS_SC_LOG_SAFE_H
