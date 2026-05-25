# 🔍 dohx · DNS over HTTPS domain intelligence tool


Fast, terminal-based domain scanner that runs everything over encrypted DNS — no raw UDP, no system resolver, no leaks. Point it at any domain and get a full picture in one shot: DNS records, TLS cert health, HTTP protocol, WHOIS/RDAP, email security posture, BGP/ASN ownership, open ports with banners, and global propagation status — all fired in parallel goroutines so the whole scan finishes in under 5 seconds.

---

## 🖥️ what it does

Run it, type a domain, pick a mode. No flags, no config files, no setup.

Three modes on the menu:

- **single record** — pick one DNS type (A, MX, TXT, etc.) and get back the answer, the TLS cert, and the HTTP protocol version all at once
- **ALL** — fires all 7 common record types in parallel plus TLS and HTTP, shows everything side by side
- **FULL SCAN** — the main event. 12+ goroutines simultaneously: DNS, TLS, HTTP security grade, RDAP/WHOIS, email security scoring, ASN/BGP ownership per IP via Team Cymru over DoH, port reachability with banner grabs, and propagation across 5 global resolvers — done before a slow dig would finish one query

Everything goes over HTTPS to your chosen resolver. Nothing touches your system's DNS stack.

```
  ·▄▄▄▄  ▄ .▄
  ██▪ ██ ██▪▐█
  ▐█· ▐█▌██▀▐█
  ██. ██ ██▌▐▀
  ▀▀▀▀▀• ▀▀▀ ·  DNS over HTTPS  ·  domain intelligence tool  ·  krainium

  [domain] example.com
  Record type

     1.  A
     2.  AAAA
     3.  MX
     4.  TXT
     5.  CNAME
     6.  NS
     7.  SOA
     8.  PTR
     9.  SRV
    10.  CAA
    11.  ALL   (7 DNS types + TLS + HTTP, parallel)
    12.  FULL SCAN  (DNS + TLS + HTTP + RDAP + Email + ASN + Ports + Propagation)
    13.  custom type

  [›] 12

  Resolver
     1.  Cloudflare 1.1.1.1
     2.  Google 8.8.8.8
     3.  Quad9 9.9.9.9
     4.  AdGuard 94.140.14.14
     5.  OpenDNS 208.67.222.222
     6.  Custom

  [›] 1

  ⟳  FULL SCAN firing 12 probes for example.com …

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   FULL SCAN   example.com  via Cloudflare 1.1.1.1
──────────────────────────────────────────────────────────────────

  A       NOERROR     (1)  84ms
    3600 s  A  93.184.216.34
  MX      NOERROR     (0)  86ms
  TXT     NOERROR     (3)  87ms
    ...

    HTTP PROTOCOL

  Protocol        HTTP/2
  Status          200
  Latency         112ms
  Server          ECS (nyb/1D1A)

  Security Grade   C

  ✓ HSTS  ✗ CSP  ✓ X-Frame  ✓ X-CTO  ✗ Referrer  ✗ Permissions

    TLS CERTIFICATE

  Subject         www.example.com
  Issuer          DigiCert Inc — DigiCert TLS RSA SHA256 2020 CA1
  Expires         2025-03-01 23:59 UTC  (280 days)
  TLS Version     TLS 1.3
  SANs            www.example.com, example.com

    RDAP / WHOIS

  Registrar       ICANN
  Created         1995-08-14
  Expires         2025-08-13
  Status          client delete prohibited, client transfer prohibited

    EMAIL SECURITY

  Score  0 / 100

  SPF             missing
  DMARC           missing
  DKIM            none found

  ⚠  No SPF record
  ⚠  No DMARC record

    ASN / BGP  (via Cymru DoH)

  93.184.216.34         AS15133  93.184.216.0/24   US  arin  EDGECAST - MCI Communications

    PORT REACHABILITY

     22  closed  SSH
     80  OPEN    HTTP      ▸
    443  OPEN    HTTPS     ▸

  2 open  9 closed

    DNS PROPAGATION  (5 global resolvers)

  Cloudflare    ✓  93.184.216.34
  Google        ✓  93.184.216.34
  AdGuard       ✓  93.184.216.34
  NextDNS       ✓  93.184.216.34
  Google(2)     ✓  93.184.216.34

  ✓  All resolvers agree

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  FULL SCAN complete
```

---

## ⚡ modes

| mode | what runs |
|---|---|
| 📌 **Single record** | DNS query + TLS cert + HTTP protocol, 3 goroutines |
| 📋 **ALL** | 7 DNS types + TLS + HTTP, 9 goroutines |
| 🔬 **FULL SCAN** | everything below, 12+ goroutines |

### 🔬 FULL SCAN covers

- 🌐 **DNS** — A, AAAA, MX, TXT, CNAME, NS, CAA in parallel
- 🔒 **TLS** — subject, issuer, expiry countdown, protocol version, SANs
- 🌍 **HTTP** — protocol detection (HTTP/1.1 / HTTP/2 / HTTP/3 via Alt-Svc), status, server, latency
- 🛡️ **HTTP security grade** — A+ to F based on HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- 📋 **RDAP / WHOIS** — registrar, creation date, expiry date, status flags, nameservers via IANA's JSON registry
- 📧 **Email security** — SPF policy strength, DMARC enforcement level (none/quarantine/reject), DKIM selector probing across 12 common selectors in parallel, BIMI + VMC check, scored 0–100
- 🗺️ **ASN / BGP** — resolves each IP to its ASN and org name by chaining DoH queries through Team Cymru's IP intelligence zone (IPv4 + IPv6), deduplicated by subnet prefix
- 🔌 **Port scan** — 11 ports concurrent TCP dial with banner grab (FTP, SSH, SMTP, HTTP, HTTPS, SMTP submission, IMAPS, POP3S, MySQL, alt-HTTP, alt-HTTPS)
- 🌎 **DNS propagation** — queries 5 geographically spread resolvers and flags any disagreements

---

## 🚀 build

requires Go 1.21+, zero external dependencies — stdlib only.

```bash
CGO_ENABLED=0 go build -o doh doh.go
./doh
```

---

## 🔌 resolvers

pick from the menu or bring your own DoH endpoint:

- 🟠 Cloudflare `1.1.1.1`
- 🔵 Google `8.8.8.8`
- 🟣 Quad9 `9.9.9.9`
- 🟢 AdGuard `94.140.14.14`
- 🔷 OpenDNS `208.67.222.222`
- ⚙️ Custom (any RFC 8484 / JSON DoH endpoint)

---

## 🔐 why DoH

standard `dig` and similar tools send DNS over plaintext UDP — visible to your ISP, network operator, or anyone on path. this tool sends every query over HTTPS to a resolver of your choice, encrypted end to end. the ASN lookups through Cymru also go over the same channel rather than raw UDP, which is a less common approach.