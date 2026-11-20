#!/usr/bin/env python3
"""
ARES OSINT 2.0 — passive OSINT framework for Kali Linux
Python 3.9+ | Standard library only

Authorized, passive collection only:
- DNS-over-HTTPS records (Google Public DNS)
- RDAP domain/IP registration data
- Certificate Transparency names (crt.sh)
- TLS certificate metadata
- HTTP response/security headers
- Reverse DNS for public IP addresses

No port scanning, exploitation, authentication attempts, brute force,
credential collection, or access to private accounts/systems.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

VERSION = "2.0.0"
USER_AGENT = f"ARES-OSINT/{VERSION} (passive research; contact: local-user)"
TIMEOUT = 12
MAX_BODY = 2_000_000
DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
}


class AresError(Exception):
    """Expected user-facing error."""


class Colors:
    enabled = sys.stdout.isatty()

    @classmethod
    def paint(cls, value: str, code: str) -> str:
        return f"\033[{code}m{value}\033[0m" if cls.enabled else value

    @classmethod
    def green(cls, s): return cls.paint(s, "32")
    @classmethod
    def red(cls, s): return cls.paint(s, "31")
    @classmethod
    def yellow(cls, s): return cls.paint(s, "33")
    @classmethod
    def cyan(cls, s): return cls.paint(s, "36")
    @classmethod
    def bold(cls, s): return cls.paint(s, "1")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_domain(raw: str) -> str:
    value = raw.strip()
    if "://" in value:
        value = urllib.parse.urlsplit(value).hostname or ""
    value = value.split("/")[0].split(":")[0].rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise AresError(f"Invalid internationalized domain: {exc}")
    if len(value) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
        value,
    ):
        raise AresError("Invalid domain. Example: example.com")
    return value


def normalize_ip(raw: str) -> str:
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        raise AresError("Invalid IPv4 or IPv6 address.")
    if not ip.is_global:
        raise AresError("Only globally routable public IP addresses are supported.")
    return str(ip)


def validate_url(raw: str) -> str:
    value = raw.strip()
    if "://" not in value:
        value = "https://" + value
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise AresError("URL must use HTTP or HTTPS and contain a hostname.")
    try:
        host = parts.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise AresError("Invalid URL hostname.")
    # Block local/private targets to reduce accidental access to internal services.
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise AresError("Private, loopback, and reserved IP targets are blocked.")
    except ValueError:
        normalize_domain(host)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def http_request(url: str, method: str = "GET", limit: int = MAX_BODY) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        method=method,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            body = response.read(limit).decode("utf-8", errors="replace")
            return {
                "status": response.status,
                "final_url": response.geturl(),
                "headers": dict(response.headers.items()),
                "body": body,
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        return {
            "status": exc.code,
            "final_url": exc.geturl(),
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "body": "",
            "error": f"HTTP {exc.code}",
        }
    except Exception as exc:
        return {"status": None, "final_url": url, "headers": {}, "body": "", "error": str(exc)}


def dns_query(name: str, record_type: str) -> dict[str, Any]:
    query = urllib.parse.urlencode({"name": name, "type": record_type})
    result = http_request(
        f"https://dns.google/resolve?{query}",
        limit=500_000,
    )
    if result["error"]:
        return {"records": [], "error": result["error"]}
    try:
        payload = json.loads(result["body"])
        answers = payload.get("Answer", [])
        return {
            "status": payload.get("Status"),
            "records": [
                {"ttl": item.get("TTL"), "data": item.get("data")}
                for item in answers
            ],
            "error": None,
        }
    except Exception as exc:
        return {"records": [], "error": f"DNS response parsing failed: {exc}"}


def collect_dns(domain: str) -> dict[str, Any]:
    output = {}
    for record_type in DNS_TYPES:
        output[record_type] = dns_query(domain, record_type)
    return output


def collect_rdap_domain(domain: str) -> dict[str, Any]:
    response = http_request(f"https://rdap.org/domain/{urllib.parse.quote(domain)}")
    if response["error"]:
        return {"error": response["error"]}
    try:
        data = json.loads(response["body"])
        return {
            "ldh_name": data.get("ldhName"),
            "handle": data.get("handle"),
            "status": data.get("status", []),
            "events": data.get("events", []),
            "nameservers": [
                item.get("ldhName") for item in data.get("nameservers", [])
                if item.get("ldhName")
            ],
            "entities": [
                {"handle": item.get("handle"), "roles": item.get("roles", [])}
                for item in data.get("entities", [])
            ],
            "error": None,
        }
    except Exception as exc:
        return {"error": f"RDAP parsing failed: {exc}"}


def collect_rdap_ip(ip: str) -> dict[str, Any]:
    response = http_request(f"https://rdap.org/ip/{urllib.parse.quote(ip)}")
    if response["error"]:
        return {"error": response["error"]}
    try:
        data = json.loads(response["body"])
        return {
            "name": data.get("name"),
            "handle": data.get("handle"),
            "start_address": data.get("startAddress"),
            "end_address": data.get("endAddress"),
            "ip_version": data.get("ipVersion"),
            "country": data.get("country"),
            "type": data.get("type"),
            "status": data.get("status", []),
            "entities": [
                {"handle": item.get("handle"), "roles": item.get("roles", [])}
                for item in data.get("entities", [])
            ],
            "error": None,
        }
    except Exception as exc:
        return {"error": f"RDAP parsing failed: {exc}"}


def collect_ct(domain: str) -> dict[str, Any]:
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    response = http_request(f"https://crt.sh/?{query}", limit=MAX_BODY)
    if response["error"]:
        return {"subdomains": [], "count": 0, "error": response["error"]}
    try:
        rows = json.loads(response["body"])
        names = set()
        for row in rows:
            for candidate in row.get("name_value", "").splitlines():
                candidate = candidate.strip().lower().lstrip("*.")
                if candidate == domain or candidate.endswith("." + domain):
                    names.add(candidate)
        return {
            "subdomains": sorted(names),
            "count": len(names),
            "source": "crt.sh Certificate Transparency",
            "error": None,
        }
    except Exception as exc:
        return {"subdomains": [], "count": 0, "error": f"CT parsing failed: {exc}"}


def collect_tls(host: str) -> dict[str, Any]:
    output = {"subject": None, "issuer": None, "not_before": None,
              "not_after": None, "san": [], "tls_version": None, "error": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as conn:
                cert = conn.getpeercert()
                output["tls_version"] = conn.version()
        output["subject"] = cert.get("subject")
        output["issuer"] = cert.get("issuer")
        output["not_before"] = cert.get("notBefore")
        output["not_after"] = cert.get("notAfter")
        output["san"] = [
            value for kind, value in cert.get("subjectAltName", [])
            if kind == "DNS"
        ]
    except Exception as exc:
        output["error"] = str(exc)
    return output


def collect_web(url: str) -> dict[str, Any]:
    response = http_request(url, method="HEAD", limit=4096)
    if response["status"] is None or response["status"] in (405, 501):
        response = http_request(url, method="GET", limit=4096)
    headers = response["headers"]
    selected = {
        key: value for key, value in headers.items()
        if key.lower() in SECURITY_HEADERS or key.lower() in {
            "server", "content-type", "content-length", "location",
            "date", "cache-control", "x-powered-by"
        }
    }
    return {
        "requested_url": url,
        "final_url": response["final_url"],
        "status": response["status"],
        "headers": selected,
        "error": response["error"],
    }


def collect_public_files(domain: str) -> dict[str, Any]:
    files = {}
    for path in ("/robots.txt", "/.well-known/security.txt", "/security.txt"):
        response = http_request(f"https://{domain}{path}", limit=50_000)
        files[path] = {
            "status": response["status"],
            "content": response["body"][:12_000] if response["status"] == 200 else None,
            "error": response["error"],
        }
    return files


def collect_reverse_dns(ip: str) -> dict[str, Any]:
    try:
        name, aliases, addresses = socket.gethostbyaddr(ip)
        return {"hostname": name, "aliases": aliases, "addresses": addresses, "error": None}
    except Exception as exc:
        return {"hostname": None, "error": str(exc)}


def resolve_host(host: str) -> dict[str, Any]:
    try:
        entries = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = sorted({item[4][0] for item in entries})
        return {"addresses": addresses, "error": None}
    except Exception as exc:
        return {"addresses": [], "error": str(exc)}


def analyze_domain(results: dict[str, Any]) -> list[dict[str, str]]:
    findings = []
    web = results.get("web", {})
    headers = {k.lower(): v for k, v in web.get("headers", {}).items()}
    for header, title, severity, advice in [
        ("strict-transport-security", "HSTS header not observed", "info",
         "Confirm HTTPS is enforced and consider deploying HSTS."),
        ("content-security-policy", "Content Security Policy not observed", "info",
         "Review whether a suitable CSP can reduce content-injection impact."),
        ("x-content-type-options", "X-Content-Type-Options not observed", "info",
         "Consider setting X-Content-Type-Options: nosniff."),
        ("x-frame-options", "Clickjacking protection header not observed", "info",
         "Review CSP frame-ancestors or X-Frame-Options."),
    ]:
        if header not in headers:
            findings.append({
                "severity": severity, "title": title,
                "evidence": f"{header} absent from observed response headers",
                "recommendation": advice,
            })
    if web.get("status") and web["status"] >= 500:
        findings.append({
            "severity": "info", "title": "Server returned a 5xx response",
            "evidence": f"HTTP status {web['status']}",
            "recommendation": "Verify service health; a single response is not conclusive.",
        })
    if not findings:
        findings.append({
            "severity": "info", "title": "No basic header observations to report",
            "evidence": "Observed response contained the checked security headers.",
            "recommendation": "Continue with a scoped, authorized security review.",
        })
    return findings


def run_tasks(tasks: dict[str, Callable[[], Any]], workers: int = 6) -> dict[str, Any]:
    results: dict[str, Any] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(fn): name for name, fn in tasks.items()}
        for future in concurrent.futures.as_completed(future_map):
            name = future_map[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                results[name] = {"error": str(exc)}
    # Keep output ordering stable.
    return {name: results.get(name, {}) for name in tasks}


def domain_report(domain: str) -> dict[str, Any]:
    print(Colors.cyan(f"\n[ARES] Passive domain assessment: {domain}"))
    tasks = {
        "dns": lambda: collect_dns(domain),
        "rdap": lambda: collect_rdap_domain(domain),
        "certificate_transparency": lambda: collect_ct(domain),
        "tls": lambda: collect_tls(domain),
        "web": lambda: collect_web(f"https://{domain}/"),
        "public_files": lambda: collect_public_files(domain),
        "resolution": lambda: resolve_host(domain),
    }
    for name in tasks:
        print(f"  [*] Queued {name}")
    results = run_tasks(tasks)
    results["findings"] = analyze_domain(results)
    return {
        "tool": "ARES OSINT",
        "version": VERSION,
        "target_type": "domain",
        "target": domain,
        "generated_at": utc_now(),
        "mode": "passive/public sources",
        "results": results,
    }


def ip_report(ip: str) -> dict[str, Any]:
    print(Colors.cyan(f"\n[ARES] Public IP assessment: {ip}"))
    tasks = {
        "rdap": lambda: collect_rdap_ip(ip),
        "reverse_dns": lambda: collect_reverse_dns(ip),
    }
    results = run_tasks(tasks)
    return {
        "tool": "ARES OSINT",
        "version": VERSION,
        "target_type": "public_ip",
        "target": ip,
        "generated_at": utc_now(),
        "mode": "passive/public sources",
        "results": results,
    }


def url_report(url: str) -> dict[str, Any]:
    print(Colors.cyan(f"\n[ARES] Passive web assessment: {url}"))
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname
    tasks = {
        "web": lambda: collect_web(url),
        "tls": lambda: collect_tls(host),
        "resolution": lambda: resolve_host(host),
    }
    results = run_tasks(tasks)
    results["findings"] = analyze_domain(results)
    return {
        "tool": "ARES OSINT",
        "version": VERSION,
        "target_type": "url",
        "target": url,
        "generated_at": utc_now(),
        "mode": "passive/public sources",
        "results": results,
    }


def print_summary(report: dict[str, Any]) -> None:
    print(Colors.bold("\n========== ARES OSINT REPORT =========="))
    print(f"Target:      {report['target']}")
    print(f"Type:        {report['target_type']}")
    print(f"Generated:   {report['generated_at']}")
    print(f"Mode:        {report['mode']}")
    results = report.get("results", {})
    if "resolution" in results:
        print("\nResolved addresses:")
        for address in results["resolution"].get("addresses", []):
            print(f"  - {address}")
    if "certificate_transparency" in results:
        ct = results["certificate_transparency"]
        print(f"\nCertificate Transparency names: {ct.get('count', 0)}")
        for name in ct.get("subdomains", [])[:40]:
            print(f"  - {name}")
        if ct.get("count", 0) > 40:
            print(f"  ... and {ct['count'] - 40} more (see JSON)")
    if "dns" in results:
        print("\nDNS records:")
        for record_type, data in results["dns"].items():
            values = [x.get("data") for x in data.get("records", [])]
            if values:
                print(f"  {record_type}: " + "; ".join(str(x) for x in values[:8]))
    if "findings" in results:
        print("\nObservations:")
        for item in results["findings"]:
            print(f"  [{item['severity'].upper()}] {item['title']}")
            print(f"      {item['recommendation']}")
    if "rdap" in results and not results["rdap"].get("error"):
        rdap = results["rdap"]
        print("\nRDAP:")
        for key in ("name", "ldh_name", "handle", "country", "start_address", "end_address"):
            if rdap.get(key):
                print(f"  {key}: {rdap[key]}")
    print(Colors.bold("\n======================================="))


def save_report(report: dict[str, Any], output: str | None) -> Path:
    if output:
        path = Path(output).expanduser()
    else:
        safe_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", report["target"])
        path = Path(f"ares_{safe_target}_{int(time.time())}.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ares",
        description="ARES OSINT 2.0 — passive intelligence collection for authorized investigations.",
        epilog="Examples: ares domain example.com | ares ip 1.1.1.1 | ares url https://example.com",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    for command, help_text in [
        ("domain", "Collect passive domain intelligence"),
        ("ip", "Collect public RDAP and reverse-DNS intelligence for a public IP"),
        ("url", "Inspect public HTTP/TLS metadata for a URL"),
    ]:
        p = sub.add_parser(command, help=help_text)
        p.add_argument("target", help="Domain, globally routable IP, or URL")
        p.add_argument("-o", "--output", help="JSON report path")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "domain":
            target = normalize_domain(args.target)
            report = domain_report(target)
        elif args.command == "ip":
            target = normalize_ip(args.target)
            report = ip_report(target)
        else:
            target = validate_url(args.target)
            report = url_report(target)

        print_summary(report)
        output = save_report(report, args.output)
        print(Colors.green(f"\n[+] JSON report saved: {output.resolve()}"))
        print(Colors.yellow("[!] Verify findings independently. Missing headers are observations, not proof of vulnerability."))
        return 0
    except AresError as exc:
        print(Colors.red(f"[!] {exc}"), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
