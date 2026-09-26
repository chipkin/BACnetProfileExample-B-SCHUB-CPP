# Third-party notices

This example's own source code (everything in this repository outside
`submodules/`) is dedicated to the public domain under [CC0-1.0](LICENSE).
Building it, however, links two third-party libraries the BACnet/SC transport
(`sc_transport/`) depends on, both fetched via [vcpkg](https://vcpkg.io/)
(see `vcpkg.json`) and both under permissive licences that allow this. Neither
is vendored into this repository - vcpkg downloads, builds, and caches each
one's own source under `build/vcpkg_installed/` (gitignored) at configure
time, and each package's own licence text ships alongside it there
(`build/vcpkg_installed/<triplet>/share/<port>/copyright`) once you have built
this example at least once.

## libwebsockets

- **Project:** <https://libwebsockets.org/> / <https://github.com/warmcat/libwebsockets>
- **Licence:** MIT
- **Used for:** the WebSocket layer of `sc_transport/ScTransport` - both the
  BACnet/SC hub-function (listener) and hub-connector roles are built on
  libwebsockets' `lws_context`/`lws_service()` API.
- **Licence text:** obtained via vcpkg
  (`build/vcpkg_installed/<triplet>/share/libwebsockets/copyright` after a
  build), or read directly from the upstream repository's `LICENSE` file. The
  MIT licence text (verbatim, from upstream):

  ```
  Copyright (c) 2010-2021 Andy Green <andy@warmcat.com> and contributors

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to
  deal in the Software without restriction, including without limitation the
  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
  sell copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
  DEALINGS IN THE SOFTWARE.
  ```

  (Individual libwebsockets source files may carry their own, compatible
  licence headers, e.g. for vendored third-party pieces inside libwebsockets
  itself - see upstream's own `LICENSE` file for the complete picture. This
  notice is not a substitute for that file.)

## OpenSSL 3

- **Project:** <https://www.openssl.org/> / <https://github.com/openssl/openssl>
- **Licence:** Apache License 2.0
- **Used for:** TLS 1.3 and X.509 certificate handling throughout
  `sc_transport/ScTransport` (both roles), certificate validation for
  certificates written over BACnet (`cert_store.cpp`), and generating lab
  certificates (`cert_tool.cpp`, `--generate-certs`).
- **Licence text:** obtained via vcpkg
  (`build/vcpkg_installed/<triplet>/share/openssl/copyright` after a build),
  or read directly from <https://www.openssl.org/source/license.html> /
  upstream's `LICENSE.txt`. The full Apache License 2.0 text is available at
  <https://www.apache.org/licenses/LICENSE-2.0>; OpenSSL's own `NOTICE`
  content (required attribution, per Apache-2.0 section 4(d)) ships with the
  vcpkg-installed copy referenced above.

## The CAS BACnet Stack

Not a third-party open-source dependency: it is a separate, commercially
licensed Chipkin product, referenced as the private git submodule
`submodules/cas-bacnet-stack`. See [README.md](README.md#licensing)
for how to obtain a licence. It is not covered by this notice, and its own
licence terms are not CC0, MIT, or Apache-2.0.
