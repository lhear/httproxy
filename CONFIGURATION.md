# Examples

## Configuration Guidelines

**Note**: Use a unique, random string for the `path` to evade network detection. Avoid predictable patterns like `/tunnel` or `/proxy`.

## Token Generation

Generate a secure bearer token. **The secret used here must match the `secret` in your server configuration.**

```bash
./server gen-token --secret <SECRET_KEY> --user <USERNAME> --exp <UNIX_TIMESTAMP>
```

### Arguments
* `--secret` / `-s`: Secret key string used for signing.
* `--user` / `-u`: Username or subject identifier.
* `--exp` / `-e`: Expiration timestamp in Unix seconds.

### Examples
```bash
./server gen-token --secret "my_secret_key" --user "admin" --exp 1768281600
```

## Keypair Generation

Generate an X25519 keypair for end-to-end encryption. **The public key will be used in the client configuration, while the private key must be kept secure on the server.**

> **Note**: End-to-end encryption is optional. If the `public_key` is not configured in the client, encryption will be disabled.

```bash
./server gen-key
```

## Client Configuration

`config.toml`:

```toml
[client]
listen = "127.0.0.1:8080"
remote = "https://your-server-domain/YOUR_SECRET_PATH"
# address = "your-server-ip"
# public_key = "your-public-key"

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

## Bypass Configuration

`bypass.json`:

```json
{
    "domain_suffix": [
        "localhost"
    ],
    "ip_cidr": [
        "10.0.0.0/8",
        "192.168.0.0/16",
        "172.16.0.0/16"
        "127.0.0.1/32",
    ]
}
```

## Server Configuration

`config.toml`:

```toml
[server]
listen = "/dev/shm/httproxy.sock"
path = "/YOUR_SECRET_PATH"
# private_key = "your-private-key"

[auth]
secret = "my_secret_key"

# [dns]
# cache_size = 1024
# client_subnet = "1.2.3.4"
# prefer_ipv6 = false
# protocol = "dot"
# upstream = "8.8.8.8:853"

# [proxy]
# socks5 = "127.0.0.1:1080"

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

## Traffic Shaping Configuration

The `traffic_shaping` field allows you to configure padding for outgoing packets to obfuscate traffic patterns. It consists of a `global` configuration and an array of `stages` for more granular control.

> **Constraint**: To ensure packets do not exceed protocol limits, all configurations must satisfy: `max(padding_range) + padding_threshold <= 16380`

> **Important**: Stages are processed sequentially based on the packet sequence. If you want a specific configuration for the 3rd packet only, you MUST define stages for the 1st and 2nd packets as placeholders.

### PaddingConfig (for `global`)

- `padding_threshold`: (usize) If the actual data length of a packet is below this threshold, padding will be applied.
- `padding_range`: ([usize; 2]) A tuple specifying the minimum and maximum random padding length to add when padding is applied.

### StageConfig (for `stages` array)

Each stage can override the `global` padding configuration for a specific range of packets.

- `count`: (Option<usize>) The last packet number for this stage (1-indexed).
- `count_range`: (Option<[usize; 2]>) A range where the second value (hi) is used as the stage's end point.

**Example:**

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

**In this example:**
- **Global Behavior**: By default, if a packet's data length is less than 1500 bytes, a random padding between 0 and 3000 bytes is added.
- **1st Packet**: The first packet will have exactly 5000 bytes of padding added, as its data length is almost certainly below the 6000-byte threshold.
- **2nd Packet**: The second packet will have a random padding between 1000 and 5000 bytes if its data length is below 3000 bytes.
- **3rd to 8th Packets**: These packets will have a random padding between 1500 and 3000 bytes if their data length is below 3000 bytes.

## Nginx Configuration

To hide the proxy server behind Nginx, use the following configuration:

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
        client_max_body_size 1m;
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
