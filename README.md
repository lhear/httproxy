# httproxy

`httproxy` is a high-performance HTTP proxy written in Rust, designed to emulate Chrome's TLS fingerprints and HTTP/2 parameters for enhanced stealth and network compatibility.

## Features

- **Fingerprint Emulation**: Leverages BoringSSL to mimic Chrome’s TLS fingerprints and HTTP/2 parameters, minimizing traffic discriminability.
- **Flexible Topology**: Engineered for seamless traversal of CDNs, Web proxies, and middleboxes, ensuring robust compatibility with complex network environments.
- **Traffic Obfuscation**: Features configurable traffic shaping with randomized padding to mitigate pattern-based traffic analysis.
- **Secure Access Control**: Enforces mandatory bearer token authentication for all client-server communication.

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
