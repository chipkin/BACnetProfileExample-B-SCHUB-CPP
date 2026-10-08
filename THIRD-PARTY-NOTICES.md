# Third-party notices

This example's own source code (everything in this repository outside
`submodules/`) is public domain under CC0-1.0; see [LICENSE](LICENSE).
Building it links three third-party libraries directly - libwebsockets and
OpenSSL (the BACnet/SC transport, `sc_transport/`) and zlib (CARI zip files,
`cari.cpp`) - plus the libraries vcpkg builds for libwebsockets itself (libuv,
and pthreads4w on Windows). All are fetched via [vcpkg](https://vcpkg.io/)
(see `vcpkg.json`) and all are under permissive licences that allow this.
None is vendored into this repository: vcpkg downloads, builds and caches each
one's source under `build/vcpkg_installed/` (gitignored) at configure time,
and each package's own licence text ships alongside it there
(`build/vcpkg_installed/<triplet>/share/<port>/copyright`) once you have built
the example at least once.

## libwebsockets

- **Project:** <https://libwebsockets.org/> / <https://github.com/warmcat/libwebsockets>
- **Licence:** MIT
- **Used for:** the WebSocket layer of `sc_transport/ScTransport` - the
  BACnet/SC hub function's listener is built on libwebsockets'
  `lws_context`/`lws_service()` API.
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
  `sc_transport/ScTransport`, certificate validation for
  certificates written over BACnet (`cert_store.cpp`), and the hub's own key
  and certificate request (`cert_tool.cpp`, `--generate-csr`).
- **Licence text:** obtained via vcpkg
  (`build/vcpkg_installed/<triplet>/share/openssl/copyright` after a build),
  or read directly from <https://www.openssl.org/source/license.html> /
  upstream's `LICENSE.txt`. The full Apache License 2.0 text is available at
  <https://www.apache.org/licenses/LICENSE-2.0>; OpenSSL's own `NOTICE`
  content (required attribution, per Apache-2.0 section 4(d)) ships with the
  vcpkg-installed copy referenced above.

## Libraries libwebsockets depends on

vcpkg builds these for libwebsockets (`vcpkg.json` doesn't name them
directly), and they are linked into the executable with it. Each one's
licence text ships in `build/vcpkg_installed/<triplet>/share/<port>/copyright`
after a build.

| Library | Licence | Project | Used for |
|---|---|---|---|
| libuv | MIT | <https://libuv.org/> | libwebsockets' event-loop backend (linked; the hub uses lws's default poll loop) |
| zlib | Zlib | <https://zlib.net/> | Reading and writing CARI certificate zip files (`cari.cpp`), and libwebsockets' compression support (not used by BACnet/SC, which is binary-framed without compression) |
| pthreads4w (`pthreads` port, Windows only) | Apache-2.0 | <https://sourceforge.net/projects/pthreads4w/> | POSIX threads on Windows, for libwebsockets |

## The CAS BACnet Stack

Not a third-party open-source dependency: it is a separate, commercially
licensed Chipkin product, referenced as the private git submodule
`submodules/cas-bacnet-stack`, with its own Chipkin licence terms. It is not
covered by this notice.
