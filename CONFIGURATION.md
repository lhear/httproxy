# httproxy Configuration Reference

Both binaries — `client` and `server` — are configured through a single
`config.toml` file passed with `-c` (default: `./config.toml`). Every
configuration key is validated at startup; unknown keys are rejected
(`deny_unknown_fields`), so a typo fails fast instead of being silently
ignored.

- [1. Command-line Utilities](#1-command-line-utilities)
- [2. Client Configuration](#2-client-configuration)
- [3. Server Configuration](#3-server-configuration)
- [4. Authentication Model](#4-authentication-model)
- [5. Traffic Shaping](#5-traffic-shaping)
- [6. Bypass Configuration](#6-bypass-configuration)
- [7. DNS Configuration](#7-dns-configuration)
- [8. Logging](#8-logging)
- [9. Resource Limits & Performance Tuning](#9-resource-limits--performance-tuning)
- [10. Deployment Behind Nginx](#10-deployment-behind-nginx)
- [11. Security & Operational Notes](#11-security--operational-notes)

---

## 1. Command-line Utilities

The `server` binary ships two subcommands for generating credentials.

### 1.1 Token Generation

Issue a bearer token (a signed JWT). **The `--secret` value must match the
`[auth] secret` of your server configuration.**

```bash
./server gen-token --secret <SECRET_KEY> --user <USERNAME> --exp <UNIX_TIMESTAMP>
```

| Argument | Required | Description                                |
| -------- | -------- | ------------------------------------------ |
| `--secret`, `-s` | yes | Signing key (must equal the server's `auth.secret`). |
| `--user`, `-u`   | yes | Username / subject identifier carried in the token. |
| `--exp`, `-e`    | yes | Expiration timestamp in Unix seconds.      |

```bash
./server gen-token --secret "my_secret_key" --user "admin" --exp 1768281600
```

### 1.2 Keypair Generation

Generate an X25519 keypair for end-to-end encryption. Place the **private
key** on the server (`[server] private_key`) and the **public key** on the
client (`[client] public_key`).

```bash
./server gen-key
```

> **Encryption is optional.** If `[client] public_key` is absent, the tunnel
> is unencrypted at the application layer (transport TLS still applies). The
> private key must be kept secret; anyone holding it can decrypt tunnel
> traffic.

---

## 2. Client Configuration

`config.toml`:

```toml
[client]
listen = "127.0.0.1:8080"
remote = "https://your-server-domain/YOUR_SECRET_PATH"
# address = "your-server-ip"
# public_key = "your-public-key"
# max_connections = 1024
# max_in_flight_bytes = 2097152
# upload_concurrency = 128

# [client.auth]
# username = "proxyuser"
# password = "proxypass"

[auth]
token = "your-token"

[bypass]
bypass_files = [
  "./bypass.json",
]

# [log]
# file_path = "client.log"
# level = "info"
# max_backups = 3

[traffic_shaping.global]
padding_range = [0, 1000]
padding_threshold = 500

[[traffic_shaping.stages]]
count = 1
padding_range = [900, 1500]
padding_threshold = 8000

[[traffic_shaping.stages]]
count_range = [2, 9]
padding_range = [800, 1200]
padding_threshold = 2000
```

### 2.1 `[client]` Reference

| Field                 | Type    | Required | Default     | Description |
| --------------------- | ------- | -------- | ----------- | ----------- |
| `listen`              | string  | yes      | —           | Local listen address, e.g. `"127.0.0.1:8080"`. |
| `remote`              | string  | yes      | —           | Full server URL including the hidden path, e.g. `"https://host/secret"`. |
| `address`             | string  | no       | host of `remote` | Overrides the resolved connection address (IP or hostname). The TLS SNI / Host header still uses the `remote` domain — useful when the server is reachable via a different IP than its certificate name. |
| `public_key`          | string  | no       | — (no encryption) | Server's X25519 public key; enables end-to-end encryption. |
| `auth`                | table   | no       | —           | Optional local proxy authentication (see §2.2). |
| `max_connections`     | integer | no       | `1024`      | Cap on concurrent local connections; excess connections are refused. Bounds client-side memory under load. |
| `max_in_flight_bytes` | integer | no       | `2097152`   | Cap on upload bytes in flight per tunnel. Trade-off between throughput and memory. **Must not exceed the server's reorder buffer (§9).** |
| `upload_concurrency`  | integer | no       | `128`       | Cap on concurrent upload POSTs per tunnel. |

### 2.2 `[client.auth]` — Local Proxy Authentication

Optional; when present the local HTTP proxy requires these credentials from
its own clients (username/password basic auth).

| Field      | Type   | Required | Description                  |
| ---------- | ------ | -------- | ---------------------------- |
| `username` | string | yes      | Proxy username.              |
| `password` | string | yes      | Proxy password.              |

### 2.3 `[auth]` — Server Authentication

| Field   | Type   | Required | Description                                        |
| ------- | ------ | -------- | -------------------------------------------------- |
| `token` | string | yes      | Bearer token presented to the server on every tunnel request (a JWT issued with `gen-token`). |

### 2.4 `[bypass]`

Optional. Routes traffic matching the rules in the referenced JSON files
directly, outside the tunnel (§6).

---

## 3. Server Configuration

`config.toml`:

```toml
[server]
listen = "/dev/shm/httproxy.sock"
path = "/YOUR_SECRET_PATH"
# private_key = "your-private-key"
# max_tunnels = 1024

[auth]
secret = "my_secret_key"

# [proxy]
# socks5 = "127.0.0.1:1080"

# [dns]
# upstream = "8.8.8.8:853"
# protocol = "dot"
# tls_domain = "dns.google"
# prefer_ipv6 = false
# cache_size = 1024
# client_subnet = "1.2.3.4"
# min_ttl = 30
# max_ttl = 3600
# swr_ttl = 3600
# empty_ttl = 300
# happy_eyeballs_delay_ms = 250
# max_concurrent_queries = 1024

# [log]
# file_path = "server.log"
# level = "info"
# max_backups = 3

[traffic_shaping.global]
padding_range = [0, 1000]
padding_threshold = 500

[[traffic_shaping.stages]]
count = 1
padding_range = [900, 1500]
padding_threshold = 8000

[[traffic_shaping.stages]]
count_range = [2, 9]
padding_range = [800, 1200]
padding_threshold = 2000
```

### 3.1 `[server]` Reference

| Field         | Type    | Required | Default | Description |
| ------------- | ------- | -------- | ------- | ----------- |
| `listen`      | string  | yes      | —       | Listen endpoint: a TCP address (`"0.0.0.0:443"`) or a Unix socket path (`"/dev/shm/httproxy.sock"`). |
| `path`        | string  | yes      | —       | Hidden service path; must match the path in the client's `remote` URL. |
| `private_key` | string  | no       | —       | X25519 private key (from `gen-key`), paired with the client's `public_key`. |
| `max_tunnels` | integer | no       | `1024`  | Cap on concurrent tunnels; excess requests receive HTTP 503. Bounds server-side memory under load. |

### 3.2 `[auth]` — JWT Signing Secret

| Field    | Type   | Required | Description |
| -------- | ------ | -------- | ----------- |
| `secret` | string | yes      | Key used to validate client bearer tokens. Must match the `--secret` used with `gen-token`. |

### 3.3 `[proxy]` — Upstream SOCKS5

| Field    | Type   | Required | Description |
| -------- | ------ | -------- | ----------- |
| `socks5` | string | no       | Optional upstream SOCKS5 proxy; all tunneled connections are routed through it. |

### 3.4 `[traffic_shaping]`

See [§5 Traffic Shaping](#5-traffic-shaping). Both sides must agree on
`encoding_type` and `max_download_bytes`.

---

## 4. Authentication Model

1. **Tunnel authentication (mandatory):** every tunnel request carries the
   client's bearer token, signed with the server's `auth.secret`. Requests
   without a valid, unexpired token are rejected.
2. **End-to-end encryption (optional):** when `public_key`/`private_key` are
   configured, a hybrid X25519 + ML-KEM key exchange seals the tunnel in
   addition to the transport TLS layer.
3. **Local proxy authentication (optional):** `[client.auth]` gates access to
   the local proxy endpoint itself.

---

## 5. Traffic Shaping

Traffic shaping obfuscates the tunnel's packet patterns in two ways:

- **Padding** — random padding appended to each frame before it is sent;
- **Inter-frame delay jitter** — a randomized (log-normal distributed) delay
  between emitted frames, applied automatically.

Padding is driven by the `[traffic_shaping]` table, shared verbatim by both
sides (the client pads, the server strips).

### 5.1 `[traffic_shaping]` Reference

| Field               | Type    | Required | Default     | Description |
| ------------------- | ------- | -------- | ----------- | ----------- |
| `global`            | table   | yes      | —           | Default padding behavior (§5.2). |
| `stages`            | array   | no       | `[]`        | Per-packet-range overrides (§5.3). |
| `encoding_type`     | string  | no       | `"binary"`  | Wire encoding: `"binary"` or `"json"`. JSON wraps frames as `{"data":"<base122>"}` lines (~14% larger, but appears as ordinary JSON traffic). |
| `max_download_bytes` | integer | no       | — (stream)  | Optional download rotation threshold. When set, the download stream is rotated into segments of this many bytes; unset streams continuously without segmentation (lower overhead). |

### 5.2 `global` — Default Padding

| Field               | Type   | Required | Description |
| ------------------- | ------ | -------- | ----------- |
| `padding_threshold` | usize  | yes      | If the frame's data length is below this value, padding is applied. |
| `padding_range`     | [usize; 2] | yes | Random padding length drawn uniformly from this inclusive range. |

### 5.3 `stages` — Per-packet Overrides

Each stage overrides the global padding for a contiguous, 1-indexed range of
packets. Stages are applied in the order in which the packet sequence number
enters their range.

| Field               | Type          | Required | Description |
| ------------------- | ------------- | -------- | ----------- |
| `count`             | usize         | one of `count`/`count_range` | Last packet number covered by this stage (1-indexed). |
| `count_range`       | [usize; 2]    | one of `count`/`count_range` | Range of packet numbers; the upper bound (hi) is the stage's end point. |
| `padding_threshold` | usize         | yes      | Same semantics as the global counterpart. |
| `padding_range`     | [usize; 2]    | yes      | Same semantics as the global counterpart. |

**Constraints:**

- `padding_range[0]` must be ≤ `padding_range[1]`; the configuration is
  rejected otherwise.
- The effective padding is capped at the frame sealing threshold minus the
  data length (the threshold is ~16 KiB of frame payload, varying slightly
  with the encoding/encryption mode); a `padding_range[1]` beyond that is
  silently truncated.
- Stages are evaluated in packet order. To configure a specific packet
  (say the 3rd), the 1st and 2nd must be covered by earlier stages or the
  global defaults — define placeholder stages when needed.

### 5.4 Example

```toml
[traffic_shaping.global]
padding_range = [0, 3000]
padding_threshold = 1500

[[traffic_shaping.stages]]
count = 1
padding_range = [5000, 5000]
padding_threshold = 6000

[[traffic_shaping.stages]]
count = 2
padding_range = [1000, 5000]
padding_threshold = 3000

[[traffic_shaping.stages]]
count_range = [3, 8]
padding_range = [1500, 3000]
padding_threshold = 3000
```

With the above configuration:

- **Default:** frames shorter than 1500 bytes receive 0–3000 bytes of padding.
- **Packet 1:** exactly 5000 bytes of padding (its data is almost certainly
  below the 6000-byte threshold).
- **Packet 2:** 1000–5000 bytes of padding when shorter than 3000 bytes.
- **Packets 3–8:** 1500–3000 bytes of padding when shorter than 3000 bytes.

---

## 6. Bypass Configuration

Optional. Traffic whose destination matches a bypass rule is sent directly,
outside the tunnel. Rules are loaded from JSON files referenced by
`[bypass] bypass_files`:

```json
{
    "domain_suffix": [
        "localhost"
    ],
    "ip_cidr": [
        "10.0.0.0/8",
        "192.168.0.0/16",
        "172.16.0.0/16",
        "127.0.0.1/32"
    ]
}
```

| Field          | Type     | Description                          |
| -------------- | -------- | ------------------------------------ |
| `domain_suffix` | string[] | Domains matched by suffix (e.g. `"localhost"` also matches `"api.localhost"`). |
| `ip_cidr`      | string[] | CIDR blocks matched against the destination IP. |

The `[bypass]` section itself is optional and defaults to empty.

---

## 7. DNS Configuration

Optional server-side DNS resolver (`[dns]`). When omitted, the system
resolver is used.

| Field                     | Type    | Required | Default    | Description |
| ------------------------- | ------- | -------- | ---------- | ----------- |
| `upstream`                | string  | yes      | —          | Upstream resolver, e.g. `"8.8.8.8:853"` (TCP/TLS when `protocol = "dot"`). |
| `protocol`                | string  | no       | `"udp"`    | `"udp"` or `"dot"` (DNS over TLS). |
| `tls_domain`              | string  | no       | —          | SNI/hostname for DoT; defaults to the `upstream` IP when absent. |
| `prefer_ipv6`             | bool    | no       | `false`    | Prefer AAAA records when connecting. |
| `cache_size`              | integer | no       | `1024`     | Number of cached responses. |
| `client_subnet`           | string  | no       | —          | EDNS Client Subnet hint. |
| `min_ttl` / `max_ttl`     | integer | no       | `30` / `3600` | Clamp for cached TTLs. |
| `swr_ttl`                 | integer | no       | `3600`     | TTL for stale-while-revalidate answers. |
| `empty_ttl`               | integer | no       | `300`      | TTL for empty (NODATA) responses. |
| `happy_eyeballs_delay_ms` | integer | no       | `250`      | Happy-Eyeballs fallback delay. |
| `max_concurrent_queries`  | integer | no       | `1024`     | Cap on in-flight queries to the upstream. |

---

## 8. Logging

The optional `[log]` section is shared by both binaries. Logs are emitted as
newline-delimited JSON (ANSI color when writing to a terminal).

| Field        | Type    | Required | Default | Description |
| ------------ | ------- | -------- | ------- | ----------- |
| `file_path`  | string  | no       | — (stdout) | Log file path; omitted logs to stdout. |
| `level`      | string  | no       | `"info"` | `trace`, `debug`, `info`, `warn` or `error`. The `RUST_LOG` environment variable takes precedence. |
| `max_backups` | integer | no       | `7`      | Number of rotated log files kept. |

---

## 9. Resource Limits & Performance Tuning

| Setting                | Default   | Bounds | Effect |
| ---------------------- | --------- | ------ | ------ |
| `[server] max_tunnels` | `1024`    | —      | Concurrent tunnels; excess → HTTP 503. |
| `[client] max_connections` | `1024` | —    | Concurrent local connections; excess are refused. |
| `[client] upload_concurrency` | `128` | —  | Concurrent upload POSTs per tunnel. |
| `[client] max_in_flight_bytes` | `2097152` (2 MiB) | ≤ server reorder buffer | Upload bytes in flight per tunnel; the throughput/memory trade-off knob. |

**Important:** the server maintains a 2 MiB per-tunnel reorder buffer.
`max_in_flight_bytes` **must not exceed 2 MiB**; a larger value causes hard
upload errors under HTTP/2 frame reordering. The default is already at the
ceiling — lower it only if you need to cap client memory.

Tuning notes:

- Raising `max_in_flight_bytes` (up to 2 MiB) and `upload_concurrency`
  increases single-tunnel upload throughput at the cost of memory; lowering
  them reduces peak memory.
- `max_connections` / `max_tunnels` are the primary bounds on total memory
  consumption under concurrent load.
- `encoding_type = "json"` trades ~14% wire overhead (base122 expansion) for
  a JSON-shaped traffic profile.
- For maximum download throughput leave `max_download_bytes` unset (direct
  streaming); setting it enables download rotation, which is primarily for
  traffic-shape purposes.

---

## 10. Deployment Behind Nginx

To front the proxy with Nginx (TLS termination, request obfuscation):

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name your-server-domain;

    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    location ^~ /YOUR_SECRET_PATH {
        access_log off;
        proxy_pass http://httproxy_backend;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_request_buffering off;
        proxy_http_version 1.1;
        client_max_body_size 4m;
        proxy_buffering off;
        proxy_buffer_size 16k;
        proxy_buffers 2 16k;
        proxy_busy_buffers_size 16k;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_set_header Connection "";
    }
    location / {
        return 404;
    }
}
upstream httproxy_backend {
    server unix:/dev/shm/httproxy.sock;
    keepalive 32;
}
```

Key points:

- `proxy_request_buffering off` and `proxy_buffering off` keep the tunnel
  streaming (required for low latency and full duplex throughput).
- Long `proxy_read/send_timeout`s prevent idle tunnel teardown.
- `client_max_body_size` must be at least the largest upload batch: batches
  reach `min(1 MiB, max_in_flight_bytes)` plus one frame of slack
  (~16 KiB), so size it accordingly (the 4m above covers any
  `max_in_flight_bytes` up to the 2 MiB ceiling).
- The Unix socket upstream (`listen = "/dev/shm/httproxy.sock"`) avoids
  loopback TCP overhead; the server may equally listen on a TCP port instead.

---

## 11. Security & Operational Notes

- **Use a unique, random `path`.** Avoid predictable patterns like `/tunnel`
  or `/proxy` — the path doubles as a capability token.
- **Use a strong, random `secret`** and rotate it with token expiry.
- **Protect the server's `private_key`**; it decrypts all tunnel traffic.
- **Expire tokens.** Keep `--exp` short enough that a leaked token has
  limited value; re-issue on rotation.
- **Validate the deployment** with the compiled binaries:

  ```bash
  ./server -c server.toml
  ./client -c client.toml
  ```

  Errors (unknown keys, invalid values, key mismatches) are reported at
  startup — a clean start means the configuration is consistent.
