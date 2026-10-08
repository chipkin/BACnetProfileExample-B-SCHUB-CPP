// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
#ifndef BSCHUB_EXAMPLE_LOG_FILE_H
#define BSCHUB_EXAMPLE_LOG_FILE_H

// log_file.h
// =============================================================================
// The log file: a copy of everything the example writes to the console, in
// logs/B-SCHUB.log under the folder it runs in, so a user can send it to
// support. The file is emptied at every start-up - one run, one file - and
// is never rotated.
//
// How: Start() points the process's stdout and stderr (file descriptors 1 and
// 2) at a pipe, and a background thread copies everything that arrives to the
// original console AND to the file. That catches every line, whoever writes
// it - CASExampleHelper::Log, plain printf, libwebsockets and the CAS BACnet
// Stack itself - without changing any of those call sites, and without
// touching the shared common/ helper (see AGENTS.md).
// =============================================================================

#include <string>

namespace LogFile {

// The log file, relative to the folder the example runs in.
static const char* const LOG_FOLDER = "logs";
static const char* const LOG_FILE_NAME = "B-SCHUB.log";

// Creates `folder` if needed, empties (or creates) `folder`/`fileName`, and
// starts copying stdout and stderr to it. Returns false (with a message on
// stderr) if that fails - the example then logs to the console only.
// *fullPath is the file's absolute path, for the start-up message.
bool Start(const std::string& folder, const std::string& fileName, std::string* fullPath);

// Flushes, stops the copy thread and puts the console back. Called
// automatically at exit (atexit); safe to call when Start() never ran.
void Stop();

}  // namespace LogFile

#endif  // BSCHUB_EXAMPLE_LOG_FILE_H
