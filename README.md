# httproxy

A high-performance HTTP proxy in Rust that emulates Chrome's TLS and HTTP/2
fingerprints, so tunnel traffic is indistinguishable from ordinary browser
traffic.

## Features

- **Fingerprint emulation** — BoringSSL configured with Chrome's TLS and HTTP/2
  parameters.
- **Flexible topology** — works through CDNs, web proxies and middleboxes.
- **Traffic obfuscation** — configurable padding and inter-frame jitter.
- **Mandatory authentication and encryption** — tunnel tokens authorise tunnel
  setup, and every tunnel is sealed with ML-KEM-768 and X25519.
- **Optional WARP egress** — non-private traffic exits through Cloudflare WARP
  (MASQUE/HTTP-3), hostnames are resolved locally, private targets stay direct.

## Getting Started

Requires a stable Rust toolchain.

```bash
cargo build --release        # → target/release/{client,server}
```

Both binaries read a `config.toml`; every key is documented in
**[CONFIGURATION.md](CONFIGURATION.md)**.

```bash
./server -c config.toml
./client -c config.toml
```

## License

**[Mozilla Public License 2.0](LICENSE)**
