// KeyPassword.h - the password for this device's private key, asked for once.
//
// A certificate package can hold a password-protected (encrypted) private key -
// the Plugfest 2026 packages do. OpenSSL asks for the password itself, on the
// console, every time something loads the key: the start-up certificate check,
// the hub listener, the HTTPS status page, and every connect attempt of the hub
// connector. The operator had to type it again and again, and a connector that
// kept retrying kept asking.
//
// Prepare() is called once at start-up. For an encrypted key it takes the
// password from the config file (sc-key-password) or asks on the console, with
// the typing hidden, checks it by decrypting the key (asking again if it's
// wrong), and keeps it in memory for the rest of the run. Everything that loads
// the key then gets it from here: libwebsockets through Get(), OpenSSL's PEM
// readers through PemCallback(). PemCallback() never prompts, so OpenSSL can no
// longer ask on its own.

#pragma once

#include <string>

namespace CASSc {
namespace KeyPassword {

// True when the PEM file holds an encrypted private key
// ("BEGIN ENCRYPTED PRIVATE KEY", or a legacy "Proc-Type: 4,ENCRYPTED" key).
bool IsEncryptedKeyFile(const std::string& keyPath);

// Call once, before anything loads the key. configPassword is the config file's
// sc-key-password ("" when not set); canPrompt is false when there is no console
// to ask on (running as a service). Returns false, with a reason in *message,
// when the key is encrypted and no working password could be had; the hub then
// starts without BACnet/SC credentials and logs why, as for any unusable key.
// *message may also carry a note on success (e.g. "password taken from the
// config file").
bool Prepare(const std::string& keyPath, const std::string& configPassword, bool canPrompt, std::string* message);

// The password Prepare() settled on, or nullptr when the key isn't encrypted
// (or none was given). Stays valid for the life of the process - libwebsockets
// keeps the pointer.
const char* Get();

// An OpenSSL pem_password_cb: copies the password Prepare() settled on. Never
// prompts; returns 0 (no password) when there is none.
int PemCallback(char* buffer, int size, int rwflag, void* userdata);

} // namespace KeyPassword
} // namespace CASSc
