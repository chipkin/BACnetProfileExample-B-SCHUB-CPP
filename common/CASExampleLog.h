// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
#ifndef CAS_EXAMPLE_LOG_H
#define CAS_EXAMPLE_LOG_H

// CASExampleLog.h
// =============================================================================
// A minimal, dependency-free structured logging facility for the example
// series, added in common/ 2.6.0.
//
// Every example today (this repo included) logs via bare printf()/
// fprintf(stderr, ...) calls scattered through main.cpp and its own transport
// code - no levels, no timestamps, and no way to turn the noise up or down.
// This is a drop-in REPLACEMENT for that pattern, not a new subsystem:
//
//   * No external logging library - just <cstdio>/<cstdarg>/<ctime>, the same
//     headers CASExampleHelper.cpp already includes.
//   * No file output or log rotation - out of scope for this pass. Output
//     still goes to stdout/stderr, exactly like the printf/fprintf calls it
//     replaces (see Log()'s own comment below for which stream each level
//     uses and why).
//   * Printf-style formatting (const char* fmt, ...), so converting an
//     existing call site is a small, mechanical edit:
//
//         printf("Warning: ignoring invalid --port \"%s\"\n", argv[i + 1]);
//         // becomes:
//         CASExampleHelper::Log(CASExampleHelper::LogLevel::Warning,
//                               "ignoring invalid --port \"%s\"", argv[i + 1]);
//
// This commit adds the facility itself, working and proven to compile, plus a
// FEW demonstrative call sites in main.cpp (see that file). It deliberately
// does NOT sweep every existing printf/fprintf call in this series over to
// it - that is a large, separate, mechanical change with real regression risk
// (this repo's RX/TX log line format, startup banner, etc. are matched
// byte-for-byte by scripts in tests/sc/) - see common/CHANGELOG.md's 2.6.0
// entry. Any later example in the series can adopt it the same way this one
// did: a #include and a handful of converted call sites, at its own pace.
// =============================================================================

namespace CASExampleHelper {

// Severity, lowest to highest. Debug is for verbose diagnostic output (e.g.
// the rate-limiting/audit-trail work planned for this repo) that must stay
// silent during normal operation unless explicitly turned on - see
// SetLogLevel below.
enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error
};

// The minimum level that actually gets printed; anything below it is
// suppressed before any formatting or I/O happens. Defaults to Info, so
// Debug output stays off unless an example opts in with
// SetLogLevel(LogLevel::Debug) - typically from its own --verbose/--debug
// command-line flag.
void SetLogLevel(LogLevel level);
LogLevel GetLogLevel();

// Print one log line - "<UTC timestamp> [<LEVEL>] <message>\n" - if level is
// at or above the current minimum (GetLogLevel()); otherwise this is a no-op
// (the message is not even formatted). Printf-style formatting: fmt and the
// varargs after it are passed straight to vsnprintf, same rules as printf.
//
// Debug/Info go to stdout, Warning/Error go to stderr - the same split
// sc_transport/ScTransport.cpp and ScTransportRouter.cpp already use for
// their own printf (FYI/status) vs fprintf(stderr, ...) (problem) calls;
// common/'s OWN printf calls (e.g. ParsePortArg's "Warning: ..." lines) predate
// this facility and are unchanged by it - see common/CHANGELOG.md.
void Log(LogLevel level, const char* fmt, ...);

} // namespace CASExampleHelper

#endif // CAS_EXAMPLE_LOG_H
