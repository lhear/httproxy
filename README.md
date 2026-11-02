# httproxy

`httproxy` is a high-performance HTTP proxy written in Rust, designed to emulate Chrome's TLS fingerprints and HTTP/2 parameters for enhanced stealth and network compatibility.

## Features

- **Fingerprint Emulation**: Leverages BoringSSL to mimic Chrome’s TLS fingerprints and HTTP/2 parameters, minimizing traffic discriminability.
- **Flexible Topology**: Engineered for seamless traversal of CDNs, Web proxies, and middleboxes, ensuring robust compatibility with complex network environments.
- **Traffic Obfuscation**: Features configurable traffic shaping with randomized padding to mitigate pattern-based traffic analysis.
- **Secure Access Control**: Enforces mandatory bearer token authentication for all client-server communication.
- **Optional WARP Egress**: The server can route all non-private outbound traffic through Cloudflare WARP over MASQUE (HTTP/3 `CONNECT`, QUIC via `quinn`), auto-registering a device on first start. Hostnames are always resolved by the built-in DNS module first — the tunnel only ever sees IP literals — and DNS queries themselves ride the same tunnel (DNS-over-TCP for port 53). Private, loopback and link-local targets stay direct.

## Getting Started

### Prerequisites

- Rust toolchain (stable)

### Building

To build both the `client` and `server` binaries:

```bash
cargo build --release
```

The compiled binaries can be found in target/release/server and target/release/client.

### Configuration

Both the client and server are configured via a `config.toml` file.

Example configurations can be found in **[CONFIGURATION.md](CONFIGURATION.md)**.

### Running

#### Server

```bash
./server -c config.toml
```

#### Client

```bash
./client -c config.toml
```

## License

This project is licensed under the **[Mozilla Public License Version 2.0](LICENSE)**.
