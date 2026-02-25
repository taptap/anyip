# AnyIP

A lightweight DNS server that resolves any IP address embedded in the hostname — with automatic TLS certificates and DNS over HTTPS.

```
dig 127-0-0-1.anyip.dev +short
# 127.0.0.1

dig myapp-192-168-1-100.anyip.dev +short
# 192.168.1.100

curl https://myapp-127-0-0-1.anyip.dev   # ✅ valid TLS, no browser warnings
```

Built for development teams who need HTTPS on local/staging services without touching `/etc/hosts` or managing certificates.

## The Problem

Modern browsers require [secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) for many Web APIs — camera (`getUserMedia`), clipboard, notifications, service workers, WebRTC, etc. On local networks, this means you either:

- Wrestle with self-signed certificates and browser exceptions on every device
- Edit `/etc/hosts` on every machine
- Give up and test on `localhost` only

AnyIP solves all three: any developer can instantly get a valid HTTPS hostname for any IP address, zero config.

## How It Works

```
Developer's browser                    AnyIP server (public)
        │                                      │
        ├─ DNS query: myapp-192-168-1-5.tap.dev ─►│
        │◄── A record: 192.168.1.5 ────────────┤
        │                                      │
        ├─ TLS handshake ──────────────────────►│ (local service on 192.168.1.5,
        │   cert: *.tap.dev (Let's Encrypt)     │  using downloaded wildcard cert)
        │◄── valid certificate ─────────────────┤
        │                                      │
        └─ secure context ✅                    │
```

Three components work together:

1. **DNS server** — resolves `<name>-<ip>.yourdomain` to the embedded IP address
2. **ACME DNS-01 responder** — automatically answers Let's Encrypt challenges so certbot can issue `*.yourdomain` wildcard certificates
3. **Certificate distribution** — serves the wildcard cert (including private key) over HTTPS for developers to download

> **Security note:** The private key is intentionally public. This provides the same security as plain HTTP — it satisfies the browser's secure context requirement, not actual transport security. See [Security](#security) for details.

## Hostname Format

All names are single-label subdomains (to stay within `*.yourdomain` wildcard coverage):

### IPv4

Replace dots with dashes. Prefix anything you want:

| Hostname | Resolves to |
|----------|-------------|
| `127-0-0-1.anyip.dev` | `127.0.0.1` |
| `myapp-192-168-1-50.anyip.dev` | `192.168.1.50` |
| `api-10-0-0-1.anyip.dev` | `10.0.0.1` |

**Rule:** the rightmost 4 dash-separated decimal octets are parsed as IPv4. Everything before is ignored (used as a label for your service).

### IPv6

Replace colons with dashes. `::` becomes `--`:

| Hostname | Resolves to |
|----------|-------------|
| `2001-db8--1.anyip.dev` | `2001:db8::1` |
| `fe80--1.anyip.dev` | `fe80::1` |
| `myapp---1.anyip.dev` | `::1` |

### Wildcard Certificate Coverage

Let's Encrypt wildcard certs cover **one level** of subdomain only:

| Hostname | Covered by `*.anyip.dev`? |
|----------|:---:|
| `myapp-127-0-0-1.anyip.dev` | ✅ |
| `api.myapp-127-0-0-1.anyip.dev` | ❌ |

Keep everything in a single label: `<name>-<ip>.anyip.dev`.

## Features

- **Embedded IP resolution** — `<anything>-<ip>.<domain>` → IP address
- **IPv4 and IPv6** — full dual-stack support
- **Automatic TLS certificates** — Let's Encrypt wildcard via DNS-01, auto-renewal
- **Certificate distribution** — download endpoint for dev teams
- **DNS over HTTPS (DoH)** — encrypted DNS via `GET` and `POST` (RFC 8484)
- **Standard DNS** — UDP and TCP on port 53
- **ACME DNS-01 responder** — built-in, no external certbot plugin needed
- **Long TTL** — 72-hour TTL for static IP mappings
- **Single binary** — zero dependencies, cross-platform

## Quick Start

### 1. Prerequisites

- A domain (e.g., `anyip.dev`) with NS records pointing to your server
- A server with a public IP and ports 53 (DNS) + 443 (HTTPS) open
- Go 1.24+ (to build) or Docker

### 2. DNS Setup

At your domain registrar, create these records:

```
anyip.dev.       NS    ns1.anyip.dev.
anyip.dev.       NS    ns2.anyip.dev.
ns1.anyip.dev.   A     <your-server-ip>
ns2.anyip.dev.   A     <your-server-ip>
```

### 3. Run the Server

```bash
go build -o anyip .
sudo ./anyip \
  -domain anyip.dev \
  -acme-email admin@anyip.dev
```

On first run, AnyIP will:
1. Start the DNS server on port 53
2. Request a wildcard certificate from Let's Encrypt via DNS-01
3. Start the DoH server on port 443 with the new certificate
4. Serve the certificate at `https://anyip.dev/cert`

### 4. Use the Certificate

Developers download the wildcard cert for their local services:

```bash
# Download cert + key
curl -o cert.pem https://anyip.dev/cert/fullchain.pem
curl -o key.pem  https://anyip.dev/cert/privkey.pem

# Use in your dev server (Node.js example)
node server.js --cert cert.pem --key key.pem --host myapp-192-168-1-5.anyip.dev
```

Or in a single line for quick setups:

```bash
# Vite
vite --https --host \
  --ssl-cert <(curl -s https://anyip.dev/cert/fullchain.pem) \
  --ssl-key <(curl -s https://anyip.dev/cert/privkey.pem)
```

## Configuration

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-domain` | `ANYIP_DOMAIN` | `anyip.dev` | Base domain |
| `-dns-addr` | `ANYIP_DNS_ADDR` | `:53` | DNS listen address (UDP+TCP) |
| `-doh-addr` | `ANYIP_DOH_ADDR` | `:443` | DoH + cert distribution (HTTPS) |
| `-doh-path` | `ANYIP_DOH_PATH` | `/dns-query` | DoH endpoint path |
| `-acme-email` | `ANYIP_ACME_EMAIL` | | Email for Let's Encrypt registration |
| `-acme-staging` | `ANYIP_ACME_STAGING` | `false` | Use Let's Encrypt staging (for testing) |
| `-cert-dir` | `ANYIP_CERT_DIR` | `./certs` | Certificate storage directory |
| `-ttl` | `ANYIP_TTL` | `259200` | DNS response TTL in seconds (72h) |
| `-only-private` | `ANYIP_ONLY_PRIVATE` | `false` | Only resolve private/reserved IPs |
| `-verbose` | `ANYIP_VERBOSE` | `false` | Verbose logging |

## DNS over HTTPS

AnyIP provides a DoH endpoint compatible with RFC 8484:

```bash
# JSON format (GET)
curl "https://anyip.dev/dns-query?name=127-0-0-1.anyip.dev&type=A" \
  -H "Accept: application/dns-json"

# Wire format (POST)
curl "https://anyip.dev/dns-query" \
  -H "Content-Type: application/dns-message" \
  -H "Accept: application/dns-message" \
  --data-binary @query.bin
```

Configure as your DNS resolver:
- **Chrome/Edge:** Settings → Security → Use secure DNS → `https://anyip.dev/dns-query`
- **Firefox:** Settings → DNS over HTTPS → `https://anyip.dev/dns-query`

## Certificate API

| Endpoint | Description |
|----------|-------------|
| `GET /cert/fullchain.pem` | Full certificate chain |
| `GET /cert/privkey.pem` | Private key |
| `GET /cert/info` | Certificate metadata (expiry, domains, fingerprint) |

Example `/cert/info` response:

```json
{
  "domains": ["anyip.dev", "*.anyip.dev"],
  "notBefore": "2026-02-25T00:00:00Z",
  "notAfter": "2026-05-26T00:00:00Z",
  "issuer": "Let's Encrypt",
  "fingerprint": "AB:CD:EF:..."
}
```

## Docker

```bash
docker run -d --name anyip \
  -p 53:53/udp -p 53:53/tcp -p 443:443 \
  -v anyip-certs:/certs \
  -e ANYIP_DOMAIN=anyip.dev \
  -e ANYIP_ACME_EMAIL=admin@anyip.dev \
  ghcr.io/nicedraft/anyip:latest
```

## Architecture

```
                    ┌─────────────────────────────────┐
                    │           AnyIP Server           │
                    │                                  │
    DNS :53 ───────►│  DNS Handler                     │
   (UDP/TCP)        │  ├─ IP queries → parse & respond │
                    │  ├─ _acme-challenge → TXT record │
                    │  └─ SOA/NS → authority records   │
                    │                                  │
   HTTPS :443 ─────►│  HTTPS Server                    │
                    │  ├─ /dns-query → DoH (RFC 8484)  │
                    │  ├─ /cert/*   → cert distribution│
                    │  └─ /         → info page        │
                    │                                  │
                    │  ACME Manager                     │
                    │  ├─ auto-request wildcard cert    │
                    │  ├─ DNS-01 challenge responder    │
                    │  └─ auto-renewal (60 days)        │
                    └─────────────────────────────────┘
```

## Security

**The wildcard private key is intentionally public.** This is by design.

AnyIP solves the browser secure context problem — not transport security. The threat model:

| Scenario | Security level |
|----------|---------------|
| Plain HTTP (`http://192.168.1.5`) | ❌ No encryption, no secure context |
| AnyIP (`https://myapp-192-168-1-5.anyip.dev`) | ⚠️ Encrypted, but public key = MITM possible. Secure context ✅ |
| Private cert (`https://myapp.internal`) | ✅ Full TLS security |

**When AnyIP is the right choice:**
- Development and testing environments
- Local network services that need `getUserMedia`, clipboard, service workers, etc.
- Staging deployments where convenience > security

**When it's NOT:**
- Production with sensitive data
- Environments where MITM attacks are a real threat

### Restricting to Private IPs

To prevent abuse (e.g., phishing with public IP certs), use `-only-private`:

```bash
anyip -domain anyip.dev -only-private
```

This restricts resolution to RFC 1918 / RFC 4193 addresses only:
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- `127.0.0.0/8` (loopback)
- `fc00::/7` (IPv6 ULA), `fe80::/10` (link-local), `::1` (loopback)

## Tech Stack

- **Go** — single binary, excellent performance, easy cross-compilation
- **[miekg/dns](https://github.com/miekg/dns)** — the de facto Go DNS library (8.6k+ ★), used by CoreDNS and Caddy
- **[golang.org/x/crypto/acme](https://pkg.go.dev/golang.org/x/crypto/acme)** — Go standard ACME client for Let's Encrypt
- **net/http** — standard library for DoH + cert distribution

## Comparison

| | AnyIP | sslip.io / nip.io | localtls |
|---|---|---|---|
| IP-in-hostname DNS | ✅ | ✅ | ✅ |
| Auto TLS certs | ✅ | ❌ | ✅ |
| Cert distribution API | ✅ | ❌ | ✅ |
| DNS over HTTPS | ✅ | ❌ | ❌ |
| IPv6 | ✅ | ✅ | ✅ |
| Private IP restriction | ✅ | ❌ | ✅ |
| Language | Go | Go | Python |
| Performance | High | High | Low |
| Maintained | ✅ | ✅ | ❌ (2023) |

## Use Cases

- **Local development** — HTTPS for camera, clipboard, service workers on `192.168.x.x`
- **Game development** — test WebRTC/WebGL features requiring secure context (TapTap Maker)
- **Mobile testing** — access dev server from phone with valid HTTPS
- **CI/CD** — deterministic DNS without external dependencies
- **Staging** — give every service a real HTTPS hostname

## License

MIT
