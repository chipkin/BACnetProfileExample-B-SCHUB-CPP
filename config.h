// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_CONFIG_H
#define BSCHUB_EXAMPLE_CONFIG_H

// config.h
// =============================================================================
// This example's `--config <path>` support: a dependency-free, INI-like
// "key = value" config file supplying DEFAULTS for a handful of this
// example's settings (device-id, port, sc-port, sc-cert-dir, sc-hub-uri,
// sc-failover-uri, dcc-password, sc-max-hub-connections).
//
// Precedence is CLI args > config file > main.cpp's own built-in defaults -
// see main.cpp's CLI-parsing block for how ExampleConfig is threaded through:
// each existing Parse*Arg() call is given the config-file value (if present)
// as ITS default, so a CLI flag (which those functions already prefer over
// their own default parameter) still wins, and a config file value only ever
// fills in what the user did not pass on the command line.
//
// Deliberately example-local (main.cpp/config.h/config.cpp), NOT common/ -
// this key set and file format is specific to this example's own CLI surface,
// and no other example in the series has a config file yet (see the series
// runbook: common/ is only for boilerplate every example shares). Kept
// dependency-free (no third-party INI/YAML/JSON library) to match this
// repository's existing ParsePortArg/ParseDeviceIdArg style in
// common/CASExampleHelper.cpp: a flat, line-oriented "key = value" format
// needs none of that machinery, and pulling one in for 8 keys would be
// exactly the kind of speculative abstraction the series avoids.
// =============================================================================

#include <stdint.h>
#include <string>

// One optional value per supported config-file key. "has*" says whether the
// key was present in the file at all - main.cpp uses that to decide whether
// to override its own compile-time default, the same way a CLI flag's mere
// presence (not its value) is what makes ParsePortArg() etc. override theirs.
struct ExampleConfig {
    bool hasDeviceId = false;
    uint32_t deviceId = 0;

    bool hasPort = false;
    uint16_t port = 0;

    bool hasScPort = false;
    uint16_t scPort = 0;

    bool hasScCertDir = false;
    std::string scCertDir;

    bool hasScHubUri = false;
    std::string scHubUri;

    bool hasScFailoverUri = false;
    std::string scFailoverUri;

    bool hasDccPassword = false;
    std::string dccPassword;

    // rate-limit: NOT included. main.cpp has no rate-limiting setting today
    // (grepped for one before writing this - see CHANGELOG.md/this task's
    // own report), so there is nothing for a config-file key to default.

    bool hasScMaxHubConnections = false;
    uint16_t scMaxHubConnections = 0;
};

// Parses "--config <path>" out of argv (same "take the next argument
// verbatim" pattern as main.cpp's own ParseStringArg); returns "" if not
// given.
std::string ParseConfigPathArg(int argc, char** argv);

// Loads a "key = value" config file (one key per line; "#" starts a comment
// to end-of-line; blank lines ignored; no [sections] - see the file header
// for why; leading/trailing whitespace around key and value is trimmed, and
// "key=value" with no spaces is also accepted). Recognised keys: device-id,
// port, sc-port, sc-cert-dir, sc-hub-uri, sc-failover-uri, dcc-password,
// sc-max-hub-connections. An unrecognised key or an unparsable numeric value
// is WARNED about (via CASExampleHelper::Log) and otherwise skipped, never
// fatal - a config file is a convenience, not a contract the device refuses
// to start over.
//
// Returns true if the file itself was found and opened (even if some lines
// inside it were skipped); false if the path could not be opened at all - the
// caller should treat that as a startup error, since the user explicitly
// named this path with --config.
bool LoadExampleConfig(const std::string& path, ExampleConfig* outConfig);

#endif // BSCHUB_EXAMPLE_CONFIG_H
