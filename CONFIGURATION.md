# Examples

## Configuration Guidelines

**Note**: Use a unique, random string for the `path` to evade network detection. Avoid predictable patterns like `/tunnel` or `/proxy`.

## Token Generation

Generate a secure bearer token:

```bash
./server gen-token -h
```

### Client Configuration

`config.json`:

```json
{
  "listen": "127.0.0.1:8080",
  "remote": "https://your-server-domain/tunnel",
  "token": "your-token",
  "log_level": "info",
  "traffic_shaping": {
    "global": {
      "padding_threshold": 500,
      "padding_range": [0, 1000]
    },
    "stages": [
      {
        "count": 1,
        "padding_threshold": 0,
        "padding_range": [900, 1500]
      },
      {
        "count_range": [2, 9],
        "padding_threshold": 2000,
        "padding_range": [800, 1200]
      }
    ]
  }
}
```

### Server Configuration

`config.json`:

```json
{
  "listen": "/dev/shm/httproxy.sock",
  "path": "/tunnel",
  "secret": "your-secret",
  "socks5_proxy": null,
  "log_level": "info",
  "dns": {
    "upstream": "8.8.8.8:853",
    "protocol": "dot",
    "prefer_ipv6": false,
    "client_subnet": null,
    "cache_size": 1024
  },
  "traffic_shaping": {
    "global": {
      "padding_threshold": 500,
      "padding_range": [0, 1000]
    },
    "stages": [
      {
        "count": 1,
        "padding_threshold": 0,
        "padding_range": [900, 1500]
      },
      {
        "count_range": [2, 9],
        "padding_threshold": 2000,
        "padding_range": [800, 1200]
      }
    ]
  }
}
```

## Traffic Shaping Configuration

The `traffic_shaping` field allows you to configure padding for outgoing packets to obfuscate traffic patterns. It consists of a `global` configuration and an array of `stages` for more granular control.

### PaddingConfig (for `global`)

- `padding_threshold`: (usize) If the actual data length of a packet is below this threshold, padding will be applied.
- `padding_range`: ([usize; 2]) A tuple specifying the minimum and maximum random padding length to add when padding is applied. For example, `[0, 3000]` means padding will be a random length between 0 and 3000 bytes.

### StageConfig (for `stages` array)

Each stage can override the `global` padding configuration for a specific range of packets.

- `count`: (Option<usize>) Applies the stage configuration to a specific packet count (1-indexed). If `count_range` is also specified, `count` takes precedence.
- `count_range`: (Option<[usize; 2]>) Applies the stage configuration to a range of packet counts. For example, `[2, 5]` applies to the 2nd, 3rd, 4th, and 5th packets.
- `padding_threshold`: (usize) Override for the global `padding_threshold` for this stage.
- `padding_range`: ([usize; 2]) Override for the global `padding_range` for this stage.

**Example:**

```json
"traffic_shaping": {
  "global": {
    "padding_threshold": 1500,
    "padding_range": [0, 3000]
  },
  "stages": [
    {
      "count": 1,  // For the very first packet
      "padding_threshold": 0,
      "padding_range": [5000, 5000] // Always add 5000 bytes of padding
    },
    {
      "count_range": [2, 5], // For packets 2 through 5
      "padding_threshold": 0,
      "padding_range": [1500, 3000]
    }
  ]
}
```

In this example:
- By default, if a packet's data length is less than 1500 bytes, a random padding between 0 and 3000 bytes is added.
- The first packet will always have 5000 bytes of padding, regardless of its data length.
- Packets from the 2nd to the 5th will have a random padding between 1500 and 3000 bytes if their data length is below the (overridden) threshold of 0 (effectively always).


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

    location ^~ /tunnel {
        access_log off;
        proxy_pass http://httproxy_backend;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_request_buffering off;
        proxy_http_version 1.1;
        client_max_body_size 0;
        proxy_buffering off;
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
