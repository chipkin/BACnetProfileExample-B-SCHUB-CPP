# `common/` — shared example helper

This folder holds the boilerplate that is identical for every example in the
BACnet profile example series, vendored into this repository so the example
builds on its own. It lets each profile's `main.cpp` stay short and read like a
tutorial, focused only on what makes that profile different.

## Versioning

`common/` carries its **own version**, separate from the example's version:
the `COMMON_VERSION` constant in `CASExampleHelper.h`, with history in
[`CHANGELOG.md`](CHANGELOG.md) (this folder's changelog, not the example's).
`PrintVersion` prints it at start-up. The folder must be **byte-identical** in
every example of the series — if this copy's version is older than the latest
`common/` changelog entry elsewhere in the series, the copy is stale.

**Never edit `common/` for one example only.** To change it: edit, bump
`COMMON_VERSION`, add a changelog entry, then re-copy the folder into every
example repository.

## What's here

| File | Purpose |
|------|---------|
| `CASExampleHelper.h` / `.cpp` | UDP socket on the BACnet/IP port + the transport/time callbacks; version/help printing; `--port` / `--deviceID` / `--dcc-password` parsing; RX/TX frame summarizing and optional `--xml` frame dump; keyboard commands (h/q/up/down); local-IPv4 / broadcast / link-speed helpers; broadcast I-Am on start-up. |
| `CASExampleLog.h` / `.cpp` | A minimal, dependency-free structured logging facility (`Debug`/`Info`/`Warning`/`Error`, timestamped, runtime-configurable minimum level) - a drop-in replacement for bare `printf`/`fprintf(stderr, ...)` calls. |
| `SimpleUDP.h` / `.cpp` | A tiny cross-platform UDP socket wrapper (Winsock on Windows, BSD sockets on Linux/macOS). |
| `CASBACnetStackExampleConstants.h` | A self-contained, series-wide copy of the BACnet enumeration values the examples use (each section names the CAS BACnet Stack header that defines the full enumeration). Identical in every example — the union of what the series needs. |
| `CHANGELOG.md` | The changelog of this folder itself (see Versioning above). |

## How `main.cpp` uses it

```cpp
// FIRST, before any other BACnetStack_* call - including anything in this helper, since
// PrintVersion() asks the stack for its version. Mandatory in every link mode.
if (!LoadBACnetFunctions()) {
    fprintf(stderr, "Error: failed to load the CAS BACnet Stack: %s\n",
            CASBACnetStackAdapter_LastError());
    return 1;
}

const uint16_t port = CASExampleHelper::ParsePortArg(argc, argv, 47808);
g_deviceInstance    = CASExampleHelper::ParseDeviceIdArg(argc, argv, g_deviceInstance);
CASExampleHelper::PrintVersion(APP_NAME, APP_VERSION);  // app + stack version
CASExampleHelper::SetupUDP(port);
CASExampleHelper::RegisterCommonCallbacks();            // receive / send / time
// ... register the example's own GetProperty callbacks, add device + objects ...
CASExampleHelper::SendIAm(g_deviceInstance);            // announce on start-up

while (running) {
    BACnetStack_Tick();
    switch (CASExampleHelper::PollKey()) { /* h / q / up / down / s */ }
}
CASExampleHelper::RestoreInput();
```

The CAS BACnet Stack (a git submodule of this repository) is reached through the C++
adapter (`adapters/cpp/CASBACnetStackAdapter.h`), so its C API is called directly as
`BACnetStack_*` — the same call whether the stack is compiled from source, linked as a
static library, or loaded from a DLL/.so at runtime. Which of those happens is a build-time
choice (`CAS_BACNET_STACK_LINK`); the code above does not change.

**That is why `LoadBACnetFunctions()` is not optional.** In DLL mode it is the call that
binds the symbols, so skipping it leaves every `BACnetStack_*` name a null pointer; in the
other modes it still runs the stack-version handshake. Call it once, at the top of `main()`,
from a single thread. See `common/CHANGELOG.md` 1.5.0.
