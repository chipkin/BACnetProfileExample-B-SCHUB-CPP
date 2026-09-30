// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// TlsKeyLog.cpp - see TlsKeyLog.h.

#include "TlsKeyLog.h"

#include <openssl/ssl.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <mutex>

namespace CASSc {
namespace TlsKeyLog {
namespace {

// OpenSSL's key log callback has no user-data pointer, so the file is
// process-wide. The mutex keeps lines from two contexts whole.
std::mutex g_mutex;
FILE* g_file = nullptr;
std::string g_path;

void WriteLine(const SSL* /*ssl*/, const char* line) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_file == nullptr || line == nullptr) {
        return;
    }
    // Flushed at once, so a capture can be decoded while the hub is still
    // running, and a crash loses nothing.
    fprintf(g_file, "%s\n", line);
    fflush(g_file);
}

}  // namespace

bool Open(const std::string& path, std::string* message) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_file != nullptr) {
        return true;
    }
    namespace fs = std::filesystem;
    std::error_code ec;
    const bool isNew = !fs::exists(path, ec);
    FILE* f = fopen(path.c_str(), "ab");
    if (f == nullptr) {
        *message = "could not open \"" + path + "\" for writing: " + std::strerror(errno);
        return false;
    }
    if (isNew) {
        // As private as a private key (on Windows only the read-only bit
        // changes; the folder's ACL is what protects it there).
        fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
    }
    g_file = f;
    g_path = path;
    return true;
}

bool IsOpen() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_file != nullptr;
}

const std::string& Path() {
    return g_path;
}

void Attach(SSL_CTX* sslCtx) {
    if (sslCtx != nullptr && IsOpen()) {
        SSL_CTX_set_keylog_callback(sslCtx, &WriteLine);
    }
}

}  // namespace TlsKeyLog
}  // namespace CASSc
