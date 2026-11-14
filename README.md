# httproxy

A high-performance HTTP proxy in Rust that carries tunnel traffic over
Chromium's own network stack, so it is indistinguishable from ordinary browser
traffic.

## Features

- **Native Chromium fingerprint** — every upstream request is issued by
  Chromium's network stack (Cronet): the browser's own TLS, HTTP/2 and QUIC
  implementation, header order and padding, with no emulation layer.
- **Flexible topology** — works through CDNs, web proxies and middleboxes.
- **Traffic obfuscation** — configurable padding and inter-frame jitter.
- **Mandatory authentication and encryption** — tunnel tokens authorise tunnel
  setup, and every tunnel is sealed with ML-KEM-768 and X25519.
- **Selective frame encryption** — TLS 1.3 ciphertext is relayed as-is instead
  of being encrypted twice, marked by one bit per frame.
- **Optional WARP egress** — non-private traffic exits through Cloudflare WARP
  (MASQUE/HTTP-3), hostnames are resolved locally, private targets stay direct.

## Getting Started

Requires a stable Rust toolchain.

```bash
cargo build --release        # → target/release/{client,server}
```

The client also needs Cronet: either build it with
`scripts/build-libcronet.sh` and point `CRONET_LIB_DIR` at the result, or leave
it out and let the client load `libcronet` at startup.

### Linking Cronet

The client talks to Chromium's network stack through Cronet. `build.rs` picks
one of two modes:

- **Static** — point `CRONET_LIB_DIR` at a directory holding a static archive
  (`libcronet.a` on Linux/macOS, `cronet.lib` on Windows). The archive is
  linked into `client`, which then has no runtime dependency.
- **Runtime loading** — leave `CRONET_LIB_DIR` unset and the client resolves
  `libcronet` at startup: `CRONET_LIB`, then next to the binary, then the
  system library path.

Cronet is not vendored here: it is compiled from Chromium's `cronet_static`
target by `scripts/build-libcronet.sh <target-triple>`. `naiveproxy.lock` pins
the one tree it comes from; the script checks that commit out, runs the tree's
own `get-clang.sh` (Chromium's clang, GN, PGO profiles, and the Debian or
OpenWrt sysroot), generates the build with Chromium's Cronet arguments, links
`cronet_static`, and packs `libcronet.a`, `cronet.link`, `VERSION` and
Chromium's `LICENSE` into `cronet/<triple>`:

```bash
sh scripts/build-libcronet.sh x86_64-unknown-linux-gnu
CRONET_LIB_DIR=cronet/x86_64-unknown-linux-gnu cargo build --release
```

Linux (glibc against Debian sysroots, musl against OpenWrt SDKs), Android
against the NDK, macOS and Windows are covered — see the matrix in
`.github/workflows/libcronet.yml`, which builds every target on each run and
passes the packages to the build jobs as artifacts. The work tree stays in
`.cronet-build/` (`CRONET_BUILD_DIR` moves it); `CRONET_DRY_RUN=1` prints a
target's GN arguments and ninja targets without touching the disk. On Windows
the package carries both `cronet.dll` and `cronet.lib`: the client links the
archive and ships as a single 13 MB file, while the DLL stays for anything that
loads Cronet at runtime instead. `CRONET_WINDOWS_STATIC=0` drops the archive
from the build.

### Using a prebuilt package

A package from another machine only needs `CRONET_LIB_DIR` pointing at its
directory; nothing here downloads one. Build it where Chromium can be compiled,
copy `cronet/<triple>` over, and the target machine needs no toolchain.

A statically linked client grows by tens of megabytes; every artifact ships
Chromium's licence as `CHROMIUM-LICENSE`. The server needs neither mode.

Both binaries read a `config.toml`; every key is documented in
**[CONFIGURATION.md](CONFIGURATION.md)**.

```bash
./server -c config.toml
./client -c config.toml
```

## License

**[Mozilla Public License 2.0](LICENSE)**
