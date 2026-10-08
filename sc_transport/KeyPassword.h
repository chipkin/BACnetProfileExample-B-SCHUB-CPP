// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see ../LICENSE.
//
// KeyPassword.h - the password for this device's private key, asked for once.
//
// A certificate package can hold a password-protected (encrypted) private key.
// Left to itself, OpenSSL asks for the password on the console every time
// something loads the key: the start-up certificate check, the hub listener,
// and every listener restart.
//
// Prepare() is called once at start-up. For an encrypted key it asks on the
// console, with the typing hidden, checks the password by decrypting the key
// (asking again if it's wrong), and keeps it in memory for the rest of the run.
// Everything that loads the key then gets it from here: libwebsockets through
// Get(), OpenSSL's PEM readers through PemCallback(). PemCallback() never
// prompts, so OpenSSL can't ask on its own.

#pragma once

#include <string>

namespace CASSc {
namespace KeyPassword {

// True when the PEM file holds an encrypted private key
// ("BEGIN ENCRYPTED PRIVATE KEY", or a legacy "Proc-Type: 4,ENCRYPTED" key).
bool IsEncryptedKeyFile(const std::string& keyPath);

// Call once, before anything loads the key. Returns false, with a reason in
// *message, when the key is encrypted and no working password was typed; the
// hub then starts without BACnet/SC credentials and logs why, as for any
// unusable key.
bool Prepare(const std::string& keyPath, std::string* message);

// The password Prepare() settled on, or nullptr when the key isn't encrypted
// (or none was given). Stays valid for the life of the process - libwebsockets
// keeps the pointer.
const char* Get();

// An OpenSSL pem_password_cb: copies the password Prepare() settled on. Never
// prompts; returns 0 (no password) when there is none.
int PemCallback(char* buffer, int size, int rwflag, void* userdata);

} // namespace KeyPassword
} // namespace CASSc
