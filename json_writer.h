// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_JSON_WRITER_H
#define BSCHUB_EXAMPLE_JSON_WRITER_H

// json_writer.h - just enough JSON output for the set-up guide's API, so the
// example needs no JSON library. Values are built inside out:
//
//   Json::Object o;
//   o.Add("name", Json::Str("hub")).Add("ok", Json::Bool(true));
//   std::string text = o.Text();   // {"name":"hub","ok":true}

#include <stdint.h>

#include <cstdio>
#include <string>

namespace Json {

// A JSON string literal, escaped. Bytes that aren't valid UTF-8 become �,
// so a certificate field with odd bytes can't break the document.
inline std::string Str(const std::string& s) {
    std::string out = "\"";
    for (size_t i = 0; i < s.size(); ++i) {
        const unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"': out += "\\\""; continue;
            case '\\': out += "\\\\"; continue;
            case '\n': out += "\\n"; continue;
            case '\r': out += "\\r"; continue;
            case '\t': out += "\\t"; continue;
            default: break;
        }
        if (c < 0x20 || c == 0x7F) {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\u%04x", c);
            out += buf;
        } else if (c < 0x80) {
            out += (char)c;
        } else {
            // Copy a valid UTF-8 sequence as it is; replace anything else.
            const size_t n = (c & 0xE0) == 0xC0 ? 2 : (c & 0xF0) == 0xE0 ? 3 : (c & 0xF8) == 0xF0 ? 4 : 0;
            bool valid = n != 0 && i + n <= s.size();
            for (size_t k = 1; valid && k < n; ++k) {
                valid = ((unsigned char)s[i + k] & 0xC0) == 0x80;
            }
            if (valid) {
                out.append(s, i, n);
                i += n - 1;
            } else {
                out += "\\ufffd";
            }
        }
    }
    return out + "\"";
}

inline std::string Bool(bool b) { return b ? "true" : "false"; }
inline std::string Num(int64_t n) { return std::to_string(n); }

class Object {
public:
    Object& Add(const std::string& key, const std::string& rawValue) {
        m_text += (m_text.empty() ? "" : ",") + Str(key) + ":" + rawValue;
        return *this;
    }
    std::string Text() const { return "{" + m_text + "}"; }
private:
    std::string m_text;
};

class Array {
public:
    Array& Add(const std::string& rawValue) {
        m_text += (m_text.empty() ? "" : ",") + rawValue;
        return *this;
    }
    bool Empty() const { return m_text.empty(); }
    std::string Text() const { return "[" + m_text + "]"; }
private:
    std::string m_text;
};

}  // namespace Json

#endif  // BSCHUB_EXAMPLE_JSON_WRITER_H
