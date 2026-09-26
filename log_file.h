// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_LOG_FILE_H
#define BSCHUB_EXAMPLE_LOG_FILE_H

// log_file.h
// =============================================================================
// --log-file: keep the hub's console output in a file too, with size-based
// rotation (issue #33), so it can run unattended - as a Windows service or a
// systemd unit - and keep its history.
//
// How: Start() points the process's stdout and stderr (file descriptors 1 and
// 2) at a pipe, and a background thread copies everything that arrives to the
// original console AND to the log file. That captures every line the process
// writes - CASExampleHelper::Log, plain printf, libwebsockets and the CAS
// BACnet Stack's own messages - without changing any of those call sites, and
// without touching the shared common/ helper (see AGENTS.md).
//
// Rotation: when the file would grow past maxBytes, it is renamed to
// <path>.1 (the old .1 becomes .2, and so on) and a new file is started;
// at most maxFiles old files are kept. The file is opened for appending, so a
// restart continues the same log.
// =============================================================================

#include <stdint.h>
#include <string>

namespace LogFile {

// Starts copying stdout/stderr to `path`. Returns false (with a message on
// stderr) if the file can't be opened or the redirection fails - the hub then
// keeps logging to the console only.
bool Start(const std::string& path, uint64_t maxBytes, unsigned maxFiles);

// Flushes and stops the copy thread, restoring the console. Safe to call when
// Start() was never called.
void Stop();

}  // namespace LogFile

#endif  // BSCHUB_EXAMPLE_LOG_FILE_H
