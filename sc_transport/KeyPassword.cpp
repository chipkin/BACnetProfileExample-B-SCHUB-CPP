// KeyPassword.cpp - see KeyPassword.h.

#include "KeyPassword.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace CASSc {
namespace KeyPassword {

namespace {

// The password for the whole run. A std::string that is never reassigned after
// Prepare(), so the c_str() handed to libwebsockets stays valid.
std::string g_password;
bool g_hasPassword = false;

// How many times a wrong password may be typed before the hub gives up asking.
const int kMaxAttempts = 3;

std::string ReadFileText(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return "";
    }
    std::ostringstream text;
    text << file.rdbuf();
    return text.str();
}

// Tries the password on the key: true when it decrypts it.
bool Unlocks(const std::string& keyText, const std::string& password) {
    BIO* bio = BIO_new_mem_buf(keyText.data(), static_cast<int>(keyText.size()));
    if (bio == nullptr) {
        return false;
    }
    // The password is passed as the callback's userdata: PEM_read_bio_PrivateKey
    // treats a non-null u with a null callback as the passphrase itself.
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, const_cast<char*>(password.c_str()));
    BIO_free(bio);
    if (key == nullptr) {
        return false;
    }
    EVP_PKEY_free(key);
    return true;
}

// Reads one line from the console with the typing hidden.
bool ReadHiddenLine(std::string* line) {
#ifdef _WIN32
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    const bool isConsole = input != INVALID_HANDLE_VALUE && GetConsoleMode(input, &mode);
    if (isConsole) {
        SetConsoleMode(input, mode & ~ENABLE_ECHO_INPUT);
    }
    const bool ok = static_cast<bool>(std::getline(std::cin, *line));
    if (isConsole) {
        SetConsoleMode(input, mode);
    }
#else
    termios previous{};
    const bool isTerminal = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &previous) == 0;
    if (isTerminal) {
        termios hidden = previous;
        hidden.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &hidden);
    }
    const bool ok = static_cast<bool>(std::getline(std::cin, *line));
    if (isTerminal) {
        tcsetattr(STDIN_FILENO, TCSANOW, &previous);
    }
#endif
    std::printf("\n");
    std::fflush(stdout);
    if (!line->empty() && line->back() == '\r') {
        line->pop_back();
    }
    return ok;
}

} // namespace

bool IsEncryptedKeyFile(const std::string& keyPath) {
    const std::string text = ReadFileText(keyPath);
    return text.find("BEGIN ENCRYPTED PRIVATE KEY") != std::string::npos ||
           text.find("Proc-Type: 4,ENCRYPTED") != std::string::npos;
}

bool Prepare(const std::string& keyPath, const std::string& configPassword, bool canPrompt, std::string* message) {
    const std::string keyText = ReadFileText(keyPath);
    if (keyText.empty() || !IsEncryptedKeyFile(keyPath)) {
        // No key yet (the "certificates missing" check reports that), or not
        // encrypted: nothing to ask for.
        return true;
    }

    if (!configPassword.empty()) {
        if (Unlocks(keyText, configPassword)) {
            g_password = configPassword;
            g_hasPassword = true;
            if (message != nullptr) {
                *message = "private key \"" + keyPath + "\" is password protected; using sc-key-password from the config file.";
            }
            return true;
        }
        if (!canPrompt) {
            if (message != nullptr) {
                *message = "sc-key-password in the config file does not unlock the private key \"" + keyPath +
                           "\". BACnet/SC can't start until it is corrected.";
            }
            return false;
        }
        std::printf("sc-key-password in the config file does not unlock \"%s\".\n", keyPath.c_str());
    } else if (!canPrompt) {
        if (message != nullptr) {
            *message = "private key \"" + keyPath + "\" is password protected and there is no console to ask on. "
                       "Put its password in the config file as sc-key-password.";
        }
        return false;
    }

    for (int attempt = 1; attempt <= kMaxAttempts; attempt++) {
        std::printf("The private key \"%s\" is password protected.\nEnter its password (it is kept in memory "
                    "only, and asked for once): ", keyPath.c_str());
        std::fflush(stdout);
        std::string typed;
        if (!ReadHiddenLine(&typed)) {
            break; // input closed
        }
        if (Unlocks(keyText, typed)) {
            g_password = typed;
            g_hasPassword = true;
            return true;
        }
        std::printf("That password does not unlock the key%s\n", attempt < kMaxAttempts ? ". Try again." : ".");
    }
    if (message != nullptr) {
        *message = "no password that unlocks the private key \"" + keyPath + "\" was entered. BACnet/SC can't start "
                   "until the hub is restarted with the right password (or sc-key-password is set in the config file).";
    }
    return false;
}

const char* Get() {
    return g_hasPassword ? g_password.c_str() : nullptr;
}

int PemCallback(char* buffer, int size, int /*rwflag*/, void* /*userdata*/) {
    if (!g_hasPassword || buffer == nullptr || size <= 0) {
        return 0;
    }
    const int length = static_cast<int>(g_password.size());
    if (length >= size) {
        return 0;
    }
    std::memcpy(buffer, g_password.data(), static_cast<size_t>(length));
    buffer[length] = '\0';
    return length;
}

} // namespace KeyPassword
} // namespace CASSc
