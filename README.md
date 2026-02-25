# AnyIP

A lightweight DNS server that resolves any IP address embedded in the hostname.

```
dig 127-0-0-1.anyip.dev +short
# 127.0.0.1

dig app.192-168-1-100.anyip.dev +short
# 192.168.1.100

dig 2001-db8--1.anyip.dev AAAA +short
# 2001:db8::1
```

Built for development teams who need instant, zero-config DNS for local and staging environments — no `/etc/hosts` editing, no DNS admin overhead.

## Features

- **Embedded IP resolution** — `<anything>.<ip>.<domain>` → IP address
- **IPv4 and IPv6** — full dual-stack support
- **DNS over HTTPS (DoH)** — modern encrypted DNS via `GET` and `POST` (RFC 8484)
- **Standard DNS** — UDP and TCP on port 53
- **Long TTL** — 72-hour TTL for static IP mappings (reduces query load)
- **Wildcard subdomains** — prefix anything: `api.staging.10-0-0-1.anyip.dev` → `10.0.0.1`
- **Single binary** — zero dependencies, cross-platform

## Hostname Format

Embed the target IP in the hostname using dash notation:

### IPv4

Replace dots with dashes:

| Hostname | Resolves to |
|----------|-------------|
| `127-0-0-1.anyip.dev` | `127.0.0.1` |
| `10-0-0-1.anyip.dev` | `10.0.0.1` |
| `app.192-168-1-50.anyip.dev` | `192.168.1.50` |
| `api.staging.172-16-0-1.anyip.dev` | `172.16.0.1` |

### IPv6

Replace colons with dashes. Use double dash for `::`:

| Hostname | Resolves to |
|----------|-------------|
| `2001-db8--1.anyip.dev` | `2001:db8::1` |
| `fe80--1.anyip.dev` | `fe80::1` |
| `app.2001-db8-0-0-0-0-0-1.anyip.dev` | `2001:db8::1` |
| `--1.anyip.dev` | `::1` |

## DNS over HTTPS

AnyIP provides a DoH endpoint compatible with RFC 8484:

```bash
# JSON format (GET)
curl -s "https://anyip.dev/dns-query?name=127-0-0-1.anyip.dev&type=A" \
  -H "Accept: application/dns-json"

# Wire format (POST)
curl -s "https://anyip.dev/dns-query" \
  -H "Content-Type: application/dns-message" \
  -H "Accept: application/dns-message" \
  --data-binary @query.bin
```

Configure in browsers and OS:
- **Chrome/Edge**: Settings → Security → Use secure DNS → Custom → `https://anyip.dev/dns-query`
- **Firefox**: Settings → DNS over HTTPS → Custom → `https://anyip.dev/dns-query`
- **macOS/iOS**: Install configuration profile (see `/docs`)
- **Android**: Private DNS → `anyip.dev`

## Quick Start

### Run from source

```bash
go run . -domain anyip.dev -dns-addr :53 -doh-addr :443 \
  -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem
```

### Run with Docker

```bash
docker run -d --name anyip \
  -p 53:53/udp -p 53:53/tcp -p 443:443 \
  -v /path/to/certs:/certs \
  -e ANYIP_DOMAIN=anyip.dev \
  -e ANYIP_TLS_CERT=/certs/cert.pem \
  -e ANYIP_TLS_KEY=/certs/key.pem \
  ghcr.io/nicedraft/anyip:latest
```

### DNS-only mode (no TLS)

```bash
go run . -domain anyip.dev -dns-addr :53 -doh-addr ""
```

## Configuration

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-domain` | `ANYIP_DOMAIN` | `anyip.dev` | Base domain |
| `-dns-addr` | `ANYIP_DNS_ADDR` | `:53` | DNS listen address (UDP+TCP) |
| `-doh-addr` | `ANYIP_DOH_ADDR` | `:443` | DoH listen address (HTTPS) |
| `-doh-path` | `ANYIP_DOH_PATH` | `/dns-query` | DoH endpoint path |
| `-tls-cert` | `ANYIP_TLS_CERT` | | TLS certificate path |
| `-tls-key` | `ANYIP_TLS_KEY` | | TLS private key path |
| `-ttl` | `ANYIP_TTL` | `259200` | Response TTL in seconds (72h) |
| `-verbose` | `ANYIP_VERBOSE` | `false` | Verbose logging |

## TLS Certificates

For production, use a wildcard certificate for your domain:

```bash
# Using Let's Encrypt with DNS-01 challenge (recommended)
certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /path/to/cloudflare.ini \
  -d "anyip.dev" -d "*.anyip.dev"
```

For local development, use [mkcert](https://github.com/FiloSottile/mkcert):

```bash
mkcert -install
mkcert "anyip.dev" "*.anyip.dev"
```

## How It Works

1. A DNS query arrives for `app.192-168-1-50.anyip.dev`
2. AnyIP strips the base domain (`.anyip.dev`), leaving `app.192-168-1-50`
3. Scans labels right-to-left to find an IP pattern: `192-168-1-50`
4. Parses it as IPv4 (`192.168.1.50`) and returns an A record
5. For IPv6, `--` is interpreted as `::`, dashes as `:`
6. TTL is set to 72 hours — the mapping never changes

## Tech Stack

- **Go** — single binary, excellent performance, easy cross-compilation
- **[miekg/dns](https://github.com/miekg/dns)** (v2) — the de facto Go DNS library, 8.6k stars, actively maintained, used by CoreDNS, Caddy, and others
- **net/http** — standard library for DoH endpoint

## Use Cases

- **Local development** — access services by IP without editing `/etc/hosts`
- **Staging environments** — give every service a real hostname
- **Virtual hosting** — run multiple vhosts on the same IP with distinct hostnames
- **CI/CD** — deterministic DNS without external dependencies
- **NAT64/DNS64** — access IPv4 addresses on IPv6-only networks via hostname

## License

MIT
