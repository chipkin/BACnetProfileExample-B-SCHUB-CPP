// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// TlsKeyLog.h - --sc-keylog-file: TLS session secrets for Wireshark (issue #68).
//
// BACnet/SC is TLS 1.3 all the way, so a packet capture of the hub shows only
// encrypted records. Wireshark can decrypt them if it is given each session's
// secrets in the NSS key log format (the file browsers write for
// SSLKEYLOGFILE). While a key log file is open, every SSL_CTX passed to
// Attach() - the BACnet/SC hub listener's and hub connector's (not the HTTPS
// status page's) - appends one line per secret to it:
//
//     CLIENT_HANDSHAKE_TRAFFIC_SECRET <client random> <secret>
//     SERVER_HANDSHAKE_TRAFFIC_SECRET ...
//     CLIENT_TRAFFIC_SECRET_0 ...   SERVER_TRAFFIC_SECRET_0 ...   EXPORTER_SECRET ...
//
// Wireshark: Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log
// filename. Anyone holding this file and a capture can read that traffic, so
// it is for debugging only: command line only, logged loudly, and reported by
// /health and the status page. It never contains a private key, and connections made while it is
// off stay undecryptable.

#pragma once

#include <string>

typedef struct ssl_ctx_st SSL_CTX;

namespace CASSc {
namespace TlsKeyLog {

// Opens `path` for appending (created owner read/write only). Call once at
// start-up, before any TLS context exists. Returns false, with the reason in
// *message, if the file can't be opened.
bool Open(const std::string& path, std::string* message);

// True once Open() has succeeded.
bool IsOpen();

// The file Open() was given ("" when none).
const std::string& Path();

// Makes every TLS session on `sslCtx` write its secrets to the open file.
// A no-op when no file is open, or for a null context.
void Attach(SSL_CTX* sslCtx);

}  // namespace TlsKeyLog
}  // namespace CASSc
