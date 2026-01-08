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
  "log_level": "info"
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
  }
}
```

## Nginx Reverse Proxy

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
