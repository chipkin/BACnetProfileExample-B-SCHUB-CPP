// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_CONFIG_H
#define BSCHUB_EXAMPLE_CONFIG_H

// config.h
// =============================================================================
// This example's `--config <path>` support: a dependency-free, INI-like
// "key = value" config file supplying DEFAULTS for a handful of this
// example's settings (device-id, port, sc-port, sc-cert-dir, sc-hub-uri,
// sc-failover-uri, dcc-password, http-port, http-bind,
// sc-max-hub-connections, sc-rate-limit).
//
// Precedence is CLI args > config file > main.cpp's own built-in defaults -
// see main.cpp's CLI-parsing block for how ExampleConfig is threaded through:
// each existing Parse*Arg() call is given the config-file value (if present)
// as ITS default, so a CLI flag (which those functions already prefer over
// their own default parameter) still wins, and a config file value only ever
// fills in what the user did not pass on the command line. dcc-password is
// the ONE exception (2026-09 secrets-handling pass): it has NO CLI flag at
// all, so the config file is the only way to set it - see README.md
// "Secrets handling" for why (a CLI argument is visible in process
// listings/shell history).
//
// Deliberately example-local (main.cpp/config.h/config.cpp), NOT common/ -
// this key set and file format is specific to this example's own CLI surface,
// and no other example in the series has a config file yet (see the series
// runbook: common/ is only for boilerplate every example shares). Kept
// dependency-free (no third-party INI/YAML/JSON library) to match this
// repository's existing ParsePortArg/ParseDeviceIdArg style in
// common/CASExampleHelper.cpp: a flat, line-oriented "key = value" format
// needs none of that machinery, and pulling one in for this many keys would
// be exactly the kind of speculative abstraction the series avoids.
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

    // dcc-password (Task 1, 2026-09 secrets-handling pass): the ONLY way to
    // set the DeviceCommunicationControl password as of this batch - the
    // "--dcc-password <string>" CLI flag was REMOVED from main.cpp (a CLI
    // argument is visible in process listings/shell history on every
    // platform - `ps aux`, Task Manager's command-line column, etc. - which
    // is a real exposure for a secret, however weak DM-DCC-B's own password
    // protection already is; see main.cpp's DeviceCommunicationControl
    // callback for that caveat). See README.md "Configuration file" and
    // "Secrets handling" for the full story, including the file-permission
    // warning LoadExampleConfig() below performs when this key is non-empty.
    bool hasDccPassword = false;
    std::string dccPassword;

    // http-port: TCP port for the read-only health/metrics HTTP endpoint
    // (Task 3) and the certificate-upload endpoint (Task 4) - both served by
    // sc_transport/HttpServer. Distinct from --port (BACnet/IP UDP) and
    // --sc-port (BACnet/SC WebSocket/TLS TCP) - three different listeners,
    // three different defaults (47808 / 47819 / 8080), no overlap.
    bool hasHttpPort = false;
    uint16_t httpPort = 0;

    // http-bind: the interface HttpServer binds to. Defaults to "127.0.0.1"
    // (loopback-only) - deliberately requiring an EXPLICIT setting to bind
    // anywhere else, since this listener has no TLS and GET /health, GET
    // /metrics have no authentication at all (see HttpServer.h's Start() doc
    // comment and README.md "Status page and HTTP endpoints" for the full risk
    // reasoning). Binding to "0.0.0.0" or a specific LAN address is a real,
    // reviewed decision this example now supports but does not default to -
    // HttpServer::Start() logs a loud warning every time it binds to
    // anything other than "127.0.0.1"/"localhost", every run, not just once,
    // so it cannot go unnoticed in a log an operator only skims.
    bool hasHttpBind = false;
    std::string httpBind;

    bool hasScMaxHubConnections = false;
    uint16_t scMaxHubConnections = 0;

    // sc-rate-limit: max NEW inbound BACnet/SC connection ATTEMPTS/second the
    // hub-function listener accepts before rejecting the excess (distinct
    // from sc-max-hub-connections, which bounds concurrent connections, not
    // the rate of new attempts) - see main.cpp's g_scRateLimit and
    // sc_transport/ScTransport::SetMaxConnectionAttemptsPerSecond. 0 means
    // "no limit". Same "has*"/value pair pattern as every other key here.
    bool hasScRateLimit = false;
    uint16_t scRateLimit = 0;
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
// http-port, http-bind, sc-max-hub-connections, sc-rate-limit. An unrecognised key or an
// unparsable numeric value is WARNED about (via CASExampleHelper::Log) and
// otherwise skipped, never fatal - a config file is a convenience, not a
// contract the device refuses to start over. If dcc-password is set to a
// non-empty value, this function ALSO warns (still non-fatal) if the config
// file itself looks readable by more than its owner/Administrators - see
// ConfigFileHasBroadPermissions() in config.cpp and README.md
// "Configuration file".
//
// Returns true if the file itself was found and opened (even if some lines
// inside it were skipped); false if the path could not be opened at all - the
// caller should treat that as a startup error, since the user explicitly
// named this path with --config.
bool LoadExampleConfig(const std::string& path, ExampleConfig* outConfig);

#endif // BSCHUB_EXAMPLE_CONFIG_H
