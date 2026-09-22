// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
// config.cpp
// =============================================================================
// Implementation of this example's --config <path> support. See config.h.
// =============================================================================

#include "config.h"
#include "CASExampleLog.h"

#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <sys/stat.h>
#endif

// Trim leading/trailing ASCII whitespace (the only kind this simple format
// needs to worry about - config files are expected to be plain ASCII/UTF-8
// key=value lines, not locale-sensitive text).
static std::string Trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && isspace((unsigned char)s[start])) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && isspace((unsigned char)s[end - 1])) {
        --end;
    }
    return s.substr(start, end - start);
}

std::string ParseConfigPathArg(const int argc, char** argv) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--config") == 0) {
            return std::string(argv[i + 1]);
        }
    }
    return std::string();
}

// Parses a config-file numeric value into *outValue, WARNING (not failing)
// on anything unparsable or out of range - same "never fatal" contract as
// the rest of this file (see config.h). "field" is the key name, used only
// for the warning message.
static bool ParseConfigUint(const std::string& field, const std::string& value,
                            const unsigned long minValue, const unsigned long maxValue,
                            uint32_t* outValue) {
    char* end = NULL;
    const unsigned long parsed = strtoul(value.c_str(), &end, 10);
    if (end == value.c_str() || *end != '\0' || parsed < minValue || parsed > maxValue) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                              "config file: ignoring \"%s = %s\" (want %lu..%lu).",
                              field.c_str(), value.c_str(), minValue, maxValue);
        return false;
    }
    *outValue = (uint32_t)parsed;
    return true;
}

#if defined(_WIN32)
// Best-effort check: true if the file's DACL grants access to a principal
// OTHER than well-known "trusted owner" SIDs (BUILTIN\Administrators,
// SYSTEM) - a rough, practical stand-in for POSIX's "group/world readable"
// on a platform with no single mode-bit to check. Deliberately NOT a full
// security audit: it does not resolve nested/domain group membership, does
// not distinguish read from write/full access, and does not walk ACEs
// inherited from a parent directory - see README.md "Secrets handling" for
// why a best-effort warning (not enforcement) is this tutorial's goal, not a
// hardened permissions check.
static bool WindowsFileHasBroadAccess(const std::string& path) {
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    const DWORD result = GetNamedSecurityInfoA(
        const_cast<char*>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
    if (result != ERROR_SUCCESS || dacl == NULL) {
        if (sd != NULL) {
            LocalFree(sd);
        }
        return false;  // can't determine - don't warn on a heuristic we can't evaluate
    }

    bool broad = false;
    for (WORD i = 0; i < dacl->AceCount; ++i) {
        LPVOID aceVoid = NULL;
        if (!GetAce(dacl, i, &aceVoid)) {
            continue;
        }
        const ACE_HEADER* header = static_cast<ACE_HEADER*>(aceVoid);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            continue;  // only ALLOW aces grant access; DENY/audit aces don't
        }
        const ACCESS_ALLOWED_ACE* ace = static_cast<ACCESS_ALLOWED_ACE*>(aceVoid);
        const PSID sid = (PSID)&ace->SidStart;
        char* sidString = NULL;
        if (ConvertSidToStringSidA(sid, &sidString)) {
            const std::string sidStr(sidString);
            LocalFree(sidString);
            // Everyone (S-1-1-0), Authenticated Users (S-1-5-11), or
            // BUILTIN\Users (S-1-5-32-545) granting ANY access is "broad" for
            // this heuristic. BUILTIN\Administrators (S-1-5-32-544) and
            // SYSTEM (S-1-5-18) are treated as trusted and never flagged.
            if (sidStr == "S-1-1-0" || sidStr == "S-1-5-11" || sidStr == "S-1-5-32-545") {
                broad = true;
                break;
            }
        }
    }
    LocalFree(sd);
    return broad;
}
#endif

// Best-effort, cross-platform "is this file readable by more than its
// owner/administrators" check - see WindowsFileHasBroadAccess's comment
// above for the Windows heuristic and its limits. POSIX just reads the mode
// bits directly (group/other read/write/execute), which is exact, unlike
// the Windows ACL heuristic.
static bool ConfigFileHasBroadPermissions(const std::string& path) {
#if defined(_WIN32)
    return WindowsFileHasBroadAccess(path);
#else
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;  // can't stat it - don't warn on a heuristic we can't evaluate
    }
    return (st.st_mode & (S_IRWXG | S_IRWXO)) != 0;
#endif
}

bool LoadExampleConfig(const std::string& path, ExampleConfig* outConfig) {
    std::ifstream file(path.c_str());
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    int lineNumber = 0;
    while (std::getline(file, line)) {
        ++lineNumber;

        // "#" starts a comment to end-of-line (see config.h's format note).
        const size_t commentPos = line.find('#');
        if (commentPos != std::string::npos) {
            line = line.substr(0, commentPos);
        }
        line = Trim(line);
        if (line.empty()) {
            continue;
        }

        const size_t equalsPos = line.find('=');
        if (equalsPos == std::string::npos) {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                                  "config file %s:%d: ignoring line with no \"=\": \"%s\".",
                                  path.c_str(), lineNumber, line.c_str());
            continue;
        }
        const std::string key = Trim(line.substr(0, equalsPos));
        const std::string value = Trim(line.substr(equalsPos + 1));
        if (key.empty()) {
            continue;
        }

        uint32_t numeric = 0;
        if (key == "device-id") {
            if (ParseConfigUint(key, value, 0, 4194302, &numeric)) {
                outConfig->deviceId = numeric;
                outConfig->hasDeviceId = true;
            }
        } else if (key == "port") {
            if (ParseConfigUint(key, value, 1, 65535, &numeric)) {
                outConfig->port = (uint16_t)numeric;
                outConfig->hasPort = true;
            }
        } else if (key == "sc-port") {
            if (ParseConfigUint(key, value, 1, 65535, &numeric)) {
                outConfig->scPort = (uint16_t)numeric;
                outConfig->hasScPort = true;
            }
        } else if (key == "sc-cert-dir") {
            outConfig->scCertDir = value;
            outConfig->hasScCertDir = true;
        } else if (key == "sc-hub-uri") {
            outConfig->scHubUri = value;
            outConfig->hasScHubUri = true;
        } else if (key == "sc-failover-uri") {
            outConfig->scFailoverUri = value;
            outConfig->hasScFailoverUri = true;
        } else if (key == "dcc-password") {
            outConfig->dccPassword = value;
            outConfig->hasDccPassword = true;
        } else if (key == "http-port") {
            if (ParseConfigUint(key, value, 1, 65535, &numeric)) {
                outConfig->httpPort = (uint16_t)numeric;
                outConfig->hasHttpPort = true;
            }
        } else if (key == "http-bind") {
            outConfig->httpBind = value;
            outConfig->hasHttpBind = true;
        } else if (key == "sc-max-hub-connections") {
            if (ParseConfigUint(key, value, 1, 65535, &numeric)) {
                outConfig->scMaxHubConnections = (uint16_t)numeric;
                outConfig->hasScMaxHubConnections = true;
            }
        } else if (key == "sc-rate-limit") {
            // 0 is a valid value here (means "no limit"), unlike
            // sc-max-hub-connections above - see config.h's comment on this field.
            if (ParseConfigUint(key, value, 0, 65535, &numeric)) {
                outConfig->scRateLimit = (uint16_t)numeric;
                outConfig->hasScRateLimit = true;
            }
        } else {
            CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
                                  "config file %s:%d: ignoring unrecognised key \"%s\".",
                                  path.c_str(), lineNumber, key.c_str());
        }
    }

    // Secrets handling (Task 1): dcc-password is the only secret-shaped key
    // this config file format currently has (every other key - device-id,
    // port, sc-port, sc-cert-dir, sc-hub-uri, sc-failover-uri, http-port,
    // sc-max-hub-connections, sc-rate-limit - is either non-sensitive or, for
    // the URIs, a network endpoint rather than a credential). Warn - do not
    // refuse to start - if the file looks readable by more than its
    // owner/Administrators, so an operator who copied a config file with the
    // wrong permissions finds out from the log instead of from an incident.
    // See ConfigFileHasBroadPermissions()'s own comment for what this check
    // does and does not catch, and README.md "Secrets handling" for the
    // icacls/chmod remediation this warning points at.
    if (outConfig->hasDccPassword && !outConfig->dccPassword.empty() &&
        ConfigFileHasBroadPermissions(path)) {
        CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
            "config file \"%s\" sets a non-empty dcc-password and appears readable by more than "
            "its owner/Administrators. Restrict its permissions: Windows - "
            "\"icacls %s /inheritance:r /grant:r %%USERNAME%%:F\"; Linux/macOS - \"chmod 600 %s\". "
            "See README.md \"Secrets handling\".",
            path.c_str(), path.c_str(), path.c_str());
    }
    return true;
}
