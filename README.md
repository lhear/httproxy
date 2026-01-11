# httproxy

`httproxy` is a high-performance HTTP proxy written in Rust, designed to emulate Chrome's TLS fingerprints and HTTP/2 parameters for enhanced stealth and network compatibility.

## Features

- **Chrome TLS & HTTP/2 Fingerprint Emulation**: Utilizes BoringSSL to mimic Chrome's network characteristics, making proxy traffic harder to distinguish from legitimate browser traffic.
- **Client-Server Architecture**: Designed for deployment in a `client -> Nginx -> server` topology, allowing for flexible and robust proxy setups.
- **Configurable Traffic Shaping**: The client and server apply configurable traffic shaping with randomized padding between data chunks to obfuscate network patterns.
- **Token-Based Authentication**: Secure communication between the client and the server is enforced using bearer token authentication.

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

Both the client and server are configured via a `config.toml` file. Example configurations can be found in **[CONFIGURATION.md](CONFIGURATION.md)**.

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
