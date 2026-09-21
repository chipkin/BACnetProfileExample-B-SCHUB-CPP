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
    return true;
}
