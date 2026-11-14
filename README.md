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

Requires a stable Rust toolchain; the client also needs Cronet.

```bash
cargo build --release        # → target/release/{client,server}
```

### Cronet

`build.rs` links Cronet statically when `CRONET_LIB_DIR` points at a package
(`libcronet.a`, or `cronet.lib` on Windows); otherwise the client resolves
`libcronet` at startup through `CRONET_LIB`, the directory next to the binary,
or the system library path.

Packages come from Chromium's `cronet_static` target, built by
`scripts/build-libcronet.sh <triple>` from the tree pinned in
`naiveproxy.lock`: glibc and musl against Debian and OpenWrt sysroots, Android
against the NDK, macOS and Windows. CI builds every target in
`.github/workflows/libcronet.yml` and hands the packages to the build jobs.

```bash
sh scripts/build-libcronet.sh x86_64-unknown-linux-gnu
CRONET_LIB_DIR=cronet/x86_64-unknown-linux-gnu cargo build --release
```

Both binaries read a `config.toml`; every key is documented in
**[CONFIGURATION.md](CONFIGURATION.md)**.

```bash
./server -c config.toml
./client -c config.toml
```

## License

**[Mozilla Public License 2.0](LICENSE)**
