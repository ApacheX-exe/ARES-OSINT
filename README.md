# ARES OSINT 2.0

Passive OSINT command-line framework for Kali Linux. Python 3.9+; standard library only.

## Features

- Domain: DNS A/AAAA/MX/NS/TXT/CAA through Google Public DNS-over-HTTPS
- Domain RDAP registration metadata
- Certificate Transparency name discovery via crt.sh
- TLS certificate metadata
- HTTP response and common security-header observations
- Public robots.txt and security.txt retrieval
- Public IP: RDAP and reverse DNS
- URL: HTTP/TLS metadata
- Concurrent collection and JSON reporting

## Safety / scope

Use only for domains, URLs, and public IPs you own or are authorized to assess.
ARES is passive: it does not scan ports, exploit services, brute-force, attempt logins,
collect credentials, or access private accounts. It blocks non-global IP targets.
Third-party services may rate-limit requests. Results are leads, not proof.

## Kali Linux setup

```bash
sudo apt update
sudo apt install -y python3
python3 --version
```

No pip dependencies are required.

## Run

```bash
python3 ares.py domain example.com
python3 ares.py ip 1.1.1.1
python3 ares.py url https://example.com
```

Specify report path:

```bash
python3 ares.py domain example.com --output reports/example.json
```

Show help:

```bash
python3 ares.py --help
python3 ares.py domain --help
```

## Optional executable command

```bash
chmod +x ares.py
sudo install -m 0755 ares.py /usr/local/bin/ares
ares domain example.com
```

## Data sources

- Google Public DNS: `dns.google`
- RDAP bootstrap service: `rdap.org`
- Certificate Transparency search: `crt.sh`
- Target's public HTTP/TLS endpoint

The framework does not guarantee completeness. DNS and CT data can be stale,
incomplete, or rate-limited. Review source responses and validate all observations.
