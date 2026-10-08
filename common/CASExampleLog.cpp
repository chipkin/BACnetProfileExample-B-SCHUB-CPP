// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
// CASExampleLog.cpp
// =============================================================================
// Implementation of the shared example logging facility. See CASExampleLog.h.
// =============================================================================

#include "CASExampleLog.h"

#include <cstdarg>
#include <cstdio>
#include <ctime>

namespace {

// Defaults to Info: Debug output is suppressed until an example explicitly
// calls CASExampleHelper::SetLogLevel(LogLevel::Debug) - see the header.
CASExampleHelper::LogLevel g_logLevel = CASExampleHelper::LogLevel::Info;

const char* LevelName(const CASExampleHelper::LogLevel level) {
    switch (level) {
        case CASExampleHelper::LogLevel::Debug:   return "DEBUG";
        case CASExampleHelper::LogLevel::Info:    return "INFO";
        case CASExampleHelper::LogLevel::Warning: return "WARNING";
        case CASExampleHelper::LogLevel::Error:   return "ERROR";
        default:                                  return "UNKNOWN";
    }
}

// A message this long already indicates something has gone wrong at the call
// site; vsnprintf still null-terminates and truncates cleanly within this, no
// heap allocation needed (same "small fixed buffer, no allocation" style as
// CASExampleHelper.cpp's own g_udpBindings table).
const size_t MAX_LOG_MESSAGE_LENGTH = 1024;

} // namespace

namespace CASExampleHelper {

void SetLogLevel(const LogLevel level) {
    g_logLevel = level;
}

LogLevel GetLogLevel() {
    return g_logLevel;
}

void Log(const LogLevel level, const char* fmt, ...) {
    if (static_cast<int>(level) < static_cast<int>(g_logLevel)) {
        return; // below the current minimum - do not even format the message
    }

    // UTC timestamp (YYYY-MM-DD HH:MM:SS), the same gmtime_s/gmtime_r pattern
    // main.cpp already uses for the File objects' Modification_Date - UTC
    // rather than localtime() so a log line means the same wall-clock instant
    // regardless of the host's configured timezone (see main.cpp's
    // GetPropertyDate/GetPropertyTime for the identical rationale).
    const time_t now = time(NULL);
    struct tm utc;
#if defined(_WIN32)
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d",
              utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
              utc.tm_hour, utc.tm_min, utc.tm_sec);

    char message[MAX_LOG_MESSAGE_LENGTH];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    // Debug/Info -> stdout, Warning/Error -> stderr - see Log()'s own doc
    // comment in CASExampleLog.h for why.
    FILE* const stream = (level == LogLevel::Warning || level == LogLevel::Error) ? stderr : stdout;
    fprintf(stream, "%s [%s] %s\n", timestamp, LevelName(level), message);
}

} // namespace CASExampleHelper
