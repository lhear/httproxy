# httproxy Configuration Reference

Both binaries read one `config.toml` (`-c`, default `./config.toml`). Unknown
keys and invalid values abort startup (`deny_unknown_fields`).

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

### 1.1 Token Generation

```bash
./server gen-token --secret <SECRET> --user <USER> --exp <UNIX_TIMESTAMP>
```

| Argument | Description |
| -------- | ----------- |
| `--secret`, `-s` | Must equal the server's `[auth] secret`. |
| `--user`, `-u` | Subject carried in the token. |
| `--exp`, `-e` | Expiry, Unix seconds. |

The token is `base64url(nonce ‖ AES-256-GCM(ver ‖ exp ‖ sub_len ‖ sub) ‖ tag)`.
The AES key is derived from `[auth] secret` with HKDF-SHA256, the subject never
appears in the clear, and verification is a single AEAD pass with no parsing.

### 1.2 Keypair Generation

```bash
./server gen-key
```

Prints an ML-KEM-768 keypair. Put the **private key** in `[server] private_key` and
the **public key** in `[client] public_key`. Both are required: the tunnel is
always sealed, and the server rejects requests that are not part of an encrypted
session.

---

## 2. Client Configuration

```toml
[client]
listen = "127.0.0.1:8080"
remote = "https://your-server-domain/YOUR_SECRET_PATH"
public_key = "your-public-key"       # required (§1.2)
# address = "your-server-ip"
# max_connections = 1024
# max_in_flight_bytes = 2097152
# upload_concurrency = 128

# [client.proxy_auth]                # local proxy basic auth (§2.2)
# username = "proxyuser"
# password = "proxypass"

[auth]
token = "your-token"

[bypass]
bypass_files = ["./bypass.json"]

[[redirect]]                         # ssh -L style, repeatable (§2.3)
listen = "127.0.0.1:2222"
target = "172.16.0.207:22"

# [log]                              # §8
# file_path = "client.log"

[traffic_shaping.global]             # staged example in §5.4
padding_range = [0, 1000]
padding_threshold = 500
```

### 2.1 `[client]` Reference

| Field                 | Type    | Required | Default     | Description |
| --------------------- | ------- | -------- | ----------- | ----------- |
| `listen`              | string  | yes      | —           | Local listen address, e.g. `"127.0.0.1:8080"`. |
| `remote`              | string  | yes      | —           | Server URL including the hidden path. |
| `address`             | string  | no       | host of `remote` | Connection address override. TLS SNI and `Host` still use the `remote` domain. |
| `public_key`          | string  | yes      | —           | Server's ML-KEM-768 encapsulation key; required for the tunnel handshake. |
| `proxy_auth`          | table   | no       | —           | Local proxy authentication (§2.2). |
| `max_connections`     | integer | no       | `1024`      | Concurrent local connections; excess are refused. |
| `max_in_flight_bytes` | integer | no       | `2097152`   | Upload bytes in flight per tunnel. **Must not exceed 2 MiB** (§9). |
| `upload_concurrency`  | integer | no       | `128`       | Concurrent upload POSTs per tunnel. |

### 2.2 `[client.proxy_auth]` — Local Proxy Authentication

When present, the local HTTP proxy requires basic auth from its clients.

| Field      | Type   | Required | Description |
| ---------- | ------ | -------- | ----------- |
| `username` | string | yes      | Proxy username. |
| `password` | string | yes      | Proxy password. |

### 2.3 `[[redirect]]` — Local Port Forwarding

Repeatable. Forwards a local TCP port through the tunnel to `target` (`ssh -L`
style); any TCP client works, no proxy support needed.

```toml
[[redirect]]
listen = "127.0.0.1:2222"    # local ip:port
target = "172.16.0.207:22"   # far side host:port
```

| Field    | Type   | Required | Description |
| -------- | ------ | -------- | ----------- |
| `listen` | string | yes      | Local `ip:port`; port `0` lets the OS pick (logged at startup). |
| `target` | string | yes      | `host:port` on the far side. Domains are resolved by the **server**. |

- Shares `max_connections` and `[[bypass]]` rules with the HTTP listener.
- The local port speaks no protocol and does no auth — do not expose it publicly.
- Invalid or duplicate `listen` values fail startup.

### 2.4 `[auth]` — Tunnel Token

| Field   | Type   | Required | Description |
| ------- | ------ | -------- | ----------- |
| `token` | string | yes      | Token that authorises opening a tunnel (from `gen-token`). |

This is separate from `[client.proxy_auth]`, which only gates the local proxy
listener.

### 2.5 `[bypass]`

Optional; routes matching traffic directly, outside the tunnel (§6).

---

## 3. Server Configuration

```toml
[server]
listen = "/dev/shm/httproxy.sock"    # or "0.0.0.0:443"
path = "/YOUR_SECRET_PATH"
private_key = "your-private-key"     # required, from `gen-key`
# max_tunnels = 1024

[auth]
secret = "my_secret_key"

# [proxy]                            # §3.3
# socks5 = "127.0.0.1:1080"

# [dns]                              # §7
# upstream = "8.8.8.8:853"
# protocol = "dot"

# [warp]                             # §3.4
# enabled = true

# [log]                              # §8
# file_path = "server.log"

[traffic_shaping.global]             # staged example in §5.4
padding_range = [0, 1000]
padding_threshold = 500
```

### 3.1 `[server]` Reference

| Field         | Type    | Required | Default | Description |
| ------------- | ------- | -------- | ------- | ----------- |
| `listen`      | string  | yes      | —       | TCP address (`"0.0.0.0:443"`) or Unix socket path. |
| `path`        | string  | yes      | —       | Hidden service path; must match the path in the client's `remote`. |
| `private_key` | string  | yes      | —       | ML-KEM-768 decapsulation key (from `gen-key`), paired with the client's `public_key`. |
| `max_tunnels` | integer | no       | `1024`  | Concurrent tunnels; excess requests get HTTP 503. |

### 3.2 `[auth]` — Token Signing Secret

| Field    | Type   | Required | Description |
| -------- | ------ | -------- | ----------- |
| `secret` | string | yes      | Secret the token key is derived from (HKDF-SHA256). Must match `gen-token --secret`. |

### 3.3 `[proxy]` — Upstream SOCKS5

| Field    | Type   | Required | Description |
| -------- | ------ | -------- | ----------- |
| `socks5` | string | no       | Upstream SOCKS5 proxy for direct connections. Ignored for `[warp]`-routed targets. |

### 3.4 `[warp]` — Optional Cloudflare WARP Egress

Carries every non-private outbound TCP connection through Cloudflare WARP.
Private targets (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`,
`100.64/10`, IPv6 `::1`, `fc00::/7`, `fe80::/10`) still go out directly.

```toml
[warp]
enabled = true
```

| Field | Type | Required | Default | Description |
| ----- | ---- | -------- | ------- | ----------- |
| `enabled` | bool | no | `true` | Set `false` to disable WARP egress. |
| `config_path` | string | no | `./warp.json` | Device credentials; auto-registered and written back (mode `0600`) when missing. |
| `endpoint` / `endpoint_v6` | string | no | registration response | WARP endpoint IP override. |
| `port` | integer | no | `443` | Endpoint UDP port. |
| `sni` | string | no | `consumer-masque-proxy.cloudflareclient.com` | TLS SNI for the L4 CONNECT gateway. |
| `connect_timeout_secs` | integer | no | `10` | QUIC handshake timeout. |
| `keepalive_secs` | integer | no | `25` | QUIC keepalive interval. |
| `idle_timeout_secs` | integer | no | `60` | QUIC idle timeout. |
| `register_model` / `register_locale` | string | no | `PC` / `en_US` | Reported during auto-registration. |
| `insecure_skip_verify` | bool | no | `false` | Disables endpoint key pinning. Troubleshooting only. |
| `bypass_private` | bool | no | `true` | Connect directly to private, loopback and link-local targets. |
| `bypass_cidrs` | string[] | no | `[]` | Extra CIDRs to connect to directly. |
| `bypass_suffixes` | string[] | no | `[]` | Extra domain suffixes to connect directly, matched per label (`corp.local` matches `db.corp.local`, not `evilcorp.local`). Resolution still goes through `[dns]`. |

Behaviour:

- **Registration**: a throwaway curve25519 key creates the account (`POST /reg`), `PATCH /reg/{id}` switches the device to MASQUE and enrols the secp256r1 key. `warp.json` is reused afterwards.
- **Transport**: one HTTP/3 `CONNECT` stream per TCP connection, all sharing one QUIC connection that is re-established on demand. Beyond Cloudflare's stream quota, `open_bi()` queues.
- **Names**: resolved locally ([`[dns]`](#7-dns-configuration), default `1.1.1.1:53`); the CONNECT `:authority` is always an IP literal. `[proxy] socks5` applies only to direct connections.
- **DNS through WARP**: public upstreams are reached as DNS-over-TCP (port 53) or DoT inside the tunnel; private or loopback upstreams stay direct.
- **Pinning**: the endpoint certificate is not publicly trusted, so the leaf SPKI is compared byte for byte with `config.peers[0].public_key`. `insecure_skip_verify = true` skips that.
- **Failures**: a failed registration aborts startup; traffic never falls back to direct connections.

### 3.5 `[traffic_shaping]`

See [§5](#5-traffic-shaping). Both sides must agree on `encoding_type` and
`max_download_bytes`.

---

## 4. Authentication Model

1. **Tunnel authorisation:** opening a tunnel requires the client's tunnel token, verified against `[auth] secret`. Later upload and download requests are bound to the tunnel by the stream cookie.
2. **End-to-end encryption (mandatory):** every tunnel is sealed by an ML-KEM-768 handshake and a hybrid X25519 + ML-KEM exchange above transport TLS. `public_key` and `private_key` are required, and requests that are not part of an encrypted session are rejected.
3. **Local proxy auth (optional):** `[client.proxy_auth]` gates the local proxy endpoint.

---

## 5. Traffic Shaping

Two mechanisms obfuscate packet patterns:

- **Padding** — random bytes appended to each frame before sending.
- **Jitter** — a log-normal random delay between emitted frames, applied automatically.

Padding is configured by `[traffic_shaping]`, shared verbatim by both sides
(the client pads, the server strips).

### 5.1 `[traffic_shaping]` Reference

| Field               | Type    | Required | Default     | Description |
| ------------------- | ------- | -------- | ----------- | ----------- |
| `global`            | table   | yes      | —           | Default padding (§5.2). |
| `stages`            | array   | no       | `[]`        | Per-packet overrides (§5.3). |
| `encoding_type`     | string  | no       | `"binary"`  | `"binary"` or `"json"`. JSON wraps frames as `{"data":"<base122>"}` lines (~14% larger, looks like ordinary JSON). |
| `max_download_bytes` | integer | no       | — (stream)  | Download rotation threshold. Unset streams continuously with lower overhead. |

### 5.2 `global` — Default Padding

| Field               | Type   | Required | Description |
| ------------------- | ------ | -------- | ----------- |
| `padding_threshold` | usize  | yes      | Pad frames whose data length is below this value. |
| `padding_range`     | [usize; 2] | yes | Random padding length, uniform in this inclusive range. |

### 5.3 `stages` — Per-packet Overrides

Each stage overrides the global padding for a contiguous, 1-indexed range of
packets.

| Field               | Type          | Required | Description |
| ------------------- | ------------- | -------- | ----------- |
| `count`             | usize         | one of `count`/`count_range` | Last packet number covered (1-indexed). |
| `count_range`       | [usize; 2]    | one of `count`/`count_range` | Packet range; the upper bound is the stage's end point. |
| `padding_threshold` | usize         | yes      | Same semantics as the global counterpart. |
| `padding_range`     | [usize; 2]    | yes      | Same semantics as the global counterpart. |

Constraints:

- `padding_range[0]` must be ≤ `padding_range[1]`, otherwise startup fails.
- Padding is capped at the frame sealing threshold minus the data length
  (~16 KiB of payload); larger values are truncated silently.
- Stages are matched in packet order, so a gap must be covered by earlier
  stages or the global defaults.

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

- **Default:** frames under 1500 B get 0–3000 B of padding.
- **Packet 1:** exactly 5000 B.
- **Packet 2:** 1000–5000 B when under 3000 B.
- **Packets 3–8:** 1500–3000 B when under 3000 B.

---

## 6. Bypass Configuration

Optional. Matching destinations are connected directly, outside the tunnel.
Rules live in the JSON files referenced by `[bypass] bypass_files`:

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

| Field          | Type     | Description |
| -------------- | -------- | ----------- |
| `domain_suffix` | string[] | Suffix match (`"localhost"` also matches `"api.localhost"`). |
| `ip_cidr`      | string[] | CIDR blocks matched against the destination IP. |

---

## 7. DNS Configuration

Optional server-side resolver. Without it the system resolver is used; with
`[warp]` enabled the default becomes `1.1.1.1:53` over WARP.

| Field                     | Type    | Required | Default    | Description |
| ------------------------- | ------- | -------- | ---------- | ----------- |
| `upstream`                | string  | yes      | —          | Upstream resolver, e.g. `"8.8.8.8:853"`. |
| `protocol`                | string  | no       | `"udp"`    | `"udp"` or `"dot"` (DNS over TLS). |
| `tls_domain`              | string  | no       | —          | SNI for DoT; defaults to the `upstream` IP. |
| `prefer_ipv6`             | bool    | no       | `false`    | Prefer AAAA records. |
| `cache_size`              | integer | no       | `1024`     | Cached responses. |
| `client_subnet`           | string  | no       | —          | EDNS Client Subnet hint. |
| `min_ttl` / `max_ttl`     | integer | no       | `30` / `3600` | Clamp for cached TTLs. |
| `swr_ttl`                 | integer | no       | `3600`     | TTL for stale-while-revalidate answers. |
| `empty_ttl`               | integer | no       | `300`      | TTL for empty (NODATA) responses. |
| `happy_eyeballs_delay_ms` | integer | no       | `250`      | Happy-Eyeballs fallback delay. |
| `max_concurrent_queries`  | integer | no       | `1024`     | In-flight queries to the upstream. |

With `[warp]`, public upstreams are queried through the tunnel
(DNS-over-TCP on 53, or DoT on 853) while private or loopback upstreams are
queried directly — point `[dns]` at a resolvable internal resolver to reach
internal names.

---

## 8. Logging

Shared by both binaries. Logs are newline-delimited JSON (ANSI colour on a
terminal).

| Field        | Type    | Required | Default | Description |
| ------------ | ------- | -------- | ------- | ----------- |
| `file_path`  | string  | no       | — (stdout) | Log file; omitted logs to stdout. |
| `level`      | string  | no       | `"info"` | `trace`, `debug`, `info`, `warn`, `error`. `RUST_LOG` takes precedence. |
| `max_backups` | integer | no       | `7`      | Rotated files kept. |

---

## 9. Resource Limits & Performance Tuning

| Setting                | Default   | Effect |
| ---------------------- | --------- | ------ |
| `[server] max_tunnels` | `1024`    | Concurrent tunnels; excess → HTTP 503. |
| `[client] max_connections` | `1024` | Concurrent local connections; excess are refused. |
| `[client] upload_concurrency` | `128` | Concurrent upload POSTs per tunnel. |
| `[client] max_in_flight_bytes` | `2097152` (2 MiB) | Upload bytes in flight per tunnel; the throughput/memory knob. |

The server keeps a **2 MiB per-tunnel reorder buffer**, so
`max_in_flight_bytes` must not exceed 2 MiB — a larger value causes hard upload
errors under HTTP/2 frame reordering. The default sits at this ceiling.

Other notes:

- `max_connections` / `max_tunnels` are the main bounds on total memory.
- `encoding_type = "json"` trades ~14% wire overhead for a JSON-shaped profile.
- Leave `max_download_bytes` unset for maximum download throughput.

---

## 10. Deployment Behind Nginx

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
        proxy_pass http://unix:/dev/shm/httproxy.sock:;
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
    }
    location / {
        return 404;
    }
}
```

- `proxy_request_buffering off` / `proxy_buffering off` keep the tunnel streaming (required for latency and full-duplex throughput); long `proxy_read/send_timeout`s prevent idle teardown.
- `client_max_body_size` must cover `min(1 MiB, max_in_flight_bytes)` plus one frame (~16 KiB); `4m` covers the 2 MiB ceiling.
- `proxy_pass http://unix:/dev/shm/httproxy.sock:` — the trailing colon forwards the original URI unchanged, which the tunnel path requires. For a TCP listener, use `proxy_pass http://127.0.0.1:8081;`.

---

## 11. Security & Operational Notes

- Use a unique, random `path`; it doubles as a capability token.
- Use a strong, random `secret` and rotate it together with token expiry.
- Protect the server's `private_key`; it decrypts all tunnel traffic.
- Keep token `--exp` short so a leaked token has limited value.
- Validate a deployment by starting both binaries with their configs — bad keys, values and mismatched credentials all fail at startup.
