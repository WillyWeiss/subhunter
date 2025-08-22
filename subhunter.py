#!/usr/bin/env python3
"""
subhunter.py

End-to-end subdomain reconnaissance: passive OSINT + DNS brute force, DNS resolution,
and HTTP(S) probing.

Highlights
- Passive sources (no key needed): crt.sh, dns.bufferover.run (Project Sonar), ThreatCrowd,
  Wayback Machine, HackerTarget (rate-limited)
- Optional paid sources: SecurityTrails, VirusTotal (keys via CLI args or env vars)
- DNS brute-force with custom or built-in wordlist
- Wildcard DNS detection to avoid false positives
- Resolves A/AAAA/CNAME, records IPs
- Async HTTP/HTTPS probe, capture status & <title>
- CSV + JSON + TXT outputs (written relative to the script directory)

Usage
  python subhunter.py -d example.com -o out --passive --bruteforce --probe

Install
  pip install aiohttp dnspython tldextract pandas

Legal
  For authorized security testing only. Respect laws and target policies.

Author: Willy Weiss
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import random
import re
import string
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import aiohttp
import dns.resolver
import tldextract

# ============================
# Models
# ============================

@dataclass
class HostRecord:
    hostname: str
    ips: List[str]
    cname: Optional[str] = None
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    http_title: Optional[str] = None
    https_title: Optional[str] = None
    http_url: Optional[str] = None
    https_url: Optional[str] = None

    def to_row(self) -> List[str]:
        return [
            self.hostname,
            ",".join(self.ips) if self.ips else "",
            self.cname or "",
            str(self.http_status) if self.http_status is not None else "",
            str(self.https_status) if self.https_status is not None else "",
            (self.http_title or "").strip(),
            (self.https_title or "").strip(),
            self.http_url or "",
            self.https_url or "",
        ]

# ============================
# Helpers
# ============================

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")


def clean_title(html: str) -> str:
    m = TITLE_RE.search(html)
    if not m:
        return ""
    title = TAG_RE.sub(" ", m.group(1))
    title = WS_RE.sub(" ", title)
    return title.strip()[:200]


def safe_filename(s: str) -> str:
    s = s.strip().replace("/", "_")
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)

# ============================
# Passive Sources
# ============================

async def fetch_json(session: aiohttp.ClientSession, url: str, **kwargs) -> Optional[dict | list]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30), **kwargs) as r:
            if r.status != 200:
                return None
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "json" in ctype:
                return await r.json(content_type=None)
            text = await r.text(errors="ignore")
            try:
                return json.loads(text)
            except Exception:
                return None
    except Exception:
        return None


async def fetch_text(session: aiohttp.ClientSession, url: str, **kwargs) -> Optional[str]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30), **kwargs) as r:
            if r.status != 200:
                return None
            return await r.text(errors="ignore")
    except Exception:
        return None


async def src_crtsh(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    data = await fetch_json(session, url)
    subs: Set[str] = set()
    if not data:
        return subs
    for item in data:  # type: ignore
        name_val = (item or {}).get("name_value", "")
        for line in str(name_val).splitlines():
            h = line.strip().lower().rstrip('.')
            if not h or h.startswith("*."):
                continue
            if h.endswith("." + domain) or h == domain:
                subs.add(h)
    return subs


async def src_bufferover(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    url = f"https://dns.bufferover.run/dns?q={domain}"
    data = await fetch_json(session, url)
    subs: Set[str] = set()
    if not data:
        return subs
    for key in ("FDNS_A", "RDNS"):
        for entry in (data.get(key) or []):  # type: ignore
            try:
                h = str(entry).split(",", 1)[1].lower().rstrip('.')
            except Exception:
                h = str(entry).lower().rstrip('.')
            if h.endswith("." + domain) or h == domain:
                subs.add(h)
    return subs


async def src_threatcrowd(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    data = await fetch_json(session, url)
    subs: Set[str] = set()
    if not data:
        return subs
    for h in (data.get("subdomains") or []):  # type: ignore
        h = str(h).lower().rstrip('.')
        if h.endswith("." + domain) or h == domain:
            subs.add(h)
    return subs


async def src_wayback(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    url = (
        "https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey"
        % domain
    )
    data = await fetch_json(session, url)
    subs: Set[str] = set()
    if not data or not isinstance(data, list):
        return subs
    for i, row in enumerate(data):
        if i == 0 and row and row[0] == "original":
            continue
        if not row:
            continue
        urlstr = str(row[0])
        m = re.match(r"^(?:https?://)?([^/]+)", urlstr)
        if not m:
            continue
        host = m.group(1).split(":")[0].lower().rstrip('.')
        if host.endswith("." + domain) or host == domain:
            subs.add(host)
    return subs


async def src_hackertarget(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    text = await fetch_text(session, url)
    subs: Set[str] = set()
    if not text or "Too many" in text or "error" in text.lower():
        return subs
    for line in text.splitlines():
        parts = line.strip().split(",")
        if not parts:
            continue
        h = parts[0].lower().rstrip('.')
        if h.endswith("." + domain) or h == domain:
            subs.add(h)
    return subs


async def src_securitytrails(session: aiohttp.ClientSession, domain: str, api_key: Optional[str]) -> Set[str]:
    if not api_key:
        return set()
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    data = await fetch_json(session, url, headers=headers)
    subs: Set[str] = set()
    if not data:
        return subs
    for s in (data.get("subdomains") or []):  # type: ignore
        subs.add(f"{s}.{domain}".lower())
    return subs


async def src_virustotal(session: aiohttp.ClientSession, domain: str, api_key: Optional[str]) -> Set[str]:
    if not api_key:
        return set()
    base = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100"
    headers = {"x-apikey": api_key}
    subs: Set[str] = set()
    cursor: Optional[str] = None
    while True:
        url = base + (f"&cursor={cursor}" if cursor else "")
        data = await fetch_json(session, url, headers=headers)
        if not data:
            break
        for item in (data.get("data") or []):  # type: ignore
            h = (item or {}).get("id", "").lower().rstrip('.')
            if h:
                subs.add(h)
        cursor = (data.get("meta", {}).get("cursor") if isinstance(data, dict) else None)  # type: ignore
        if not cursor:
            break
    return subs


async def gather_passive(domain: str, vt_key: Optional[str], st_key: Optional[str]) -> Set[str]:
    timeout = aiohttp.ClientTimeout(total=45)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = [
            # API sources (optional)
            src_securitytrails(session, domain, st_key),
            src_virustotal(session, domain, vt_key),
            # non-API sources
            src_crtsh(session, domain),
            src_bufferover(session, domain),
            src_threatcrowd(session, domain),
            src_wayback(session, domain),
            src_hackertarget(session, domain),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    subs: Set[str] = set()
    for r in results:
        if isinstance(r, set):
            subs.update(r)
    suffix = "." + domain
    return {h for h in subs if h.endswith(suffix) or h == domain}

# ============================
# DNS & Brute Force
# ============================

def load_wordlist(path: Optional[Path]) -> List[str]:
    if path and path.exists():
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            return [w.strip() for w in f if w.strip() and not w.startswith("#")]
    # sensible built-in
    return [
        "www","mail","dev","staging","api","test","admin","portal","vpn","m","blog","shop",
        "ftp","gw","cdn","assets","img","static","beta","dash","jira","confluence","git",
        "gitlab","ci","ns1","ns2","db","mysql","postgres","redis","cache","search","sso",
        "auth","proxy","office","intranet","remote","status","app","apps","monitor",
        "grafana","prometheus","kibana","elk","smtp","imap","pop","owa","autodiscover",
        "cpanel","pma","tracking","analytics","newsletter","pay","billing","secure","files",
        "download","upload","media","video","help","support","ticket","tickets","docs",
        "doc","wiki","stage","qa","preprod","prod","dev1","dev2","uat","sonar","vault",
        "internal","private","gateway","store","id","identity","oidc","saml","crm","erp",
        "hr","sap","sales","partners"
    ]


def detect_wildcard(domain: str, resolver: dns.resolver.Resolver) -> Optional[Set[str]]:
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    test = f"{rand}.{domain}"
    for rtype in ("A", "AAAA"):
        try:
            ans = resolver.resolve(test, rtype)
            ips = {getattr(r, 'address', None) for r in ans}
            ips = {ip for ip in ips if ip}
            if ips:
                return ips
        except Exception:
            pass
    return None


def resolve_hostname(host: str, resolver: dns.resolver.Resolver) -> Tuple[List[str], Optional[str]]:
    ips: Set[str] = set()
    cname: Optional[str] = None
    try:
        try:
            c = resolver.resolve(host, "CNAME")
            for r in c:
                cname = str(r.target).rstrip('.')
        except Exception:
            pass
        for rtype in ("A", "AAAA"):
            try:
                ans = resolver.resolve(host, rtype)
                for r in ans:
                    addr = getattr(r, 'address', None)
                    if addr:
                        ips.add(addr)
            except Exception:
                pass
    except Exception:
        pass
    return sorted(ips), cname


async def brute_force(domain: str, words: List[str], concurrency: int, nameservers: Optional[List[str]]) -> Set[str]:
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
    resolver.lifetime = 2.5
    resolver.timeout = 2.5

    wildcard_ips = detect_wildcard(domain, resolver)
    discovered: Set[str] = set()
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)

    async def worker(w: str):
        host = f"{w}.{domain}".lower()
        async with sem:
            ips, _ = await loop.run_in_executor(None, resolve_hostname, host, resolver)
        if ips:
            if wildcard_ips and set(ips).issubset(wildcard_ips):
                return
            discovered.add(host)

    tasks = [asyncio.create_task(worker(w)) for w in words]
    for i in range(0, len(tasks), 1000):
        await asyncio.gather(*tasks[i:i+1000], return_exceptions=True)
    return discovered

# ============================
# HTTP(S) Probing
# ============================

async def probe_one(session: aiohttp.ClientSession, url: str) -> Tuple[Optional[int], Optional[str]]:
    try:
        async with session.get(url, allow_redirects=True) as r:
            status = r.status
            text = await r.text(errors="ignore")
            return status, clean_title(text)
    except Exception:
        return None, None


async def probe_http(hosts: Iterable[str], concurrency: int) -> Dict[str, Dict[str, Tuple[Optional[int], Optional[str]]]]:
    timeout = aiohttp.ClientTimeout(total=15, connect=5)
    conn = aiohttp.TCPConnector(ssl=False, limit_per_host=concurrency)
    results: Dict[str, Dict[str, Tuple[Optional[int], Optional[str]]]] = {}

    async with aiohttp.ClientSession(timeout=timeout, connector=conn) as session:
        sem = asyncio.Semaphore(concurrency)

        async def worker(host: str):
            d: Dict[str, Tuple[Optional[int], Optional[str]]] = {"http": (None, None), "https": (None, None)}
            for scheme in ("http", "https"):
                url = f"{scheme}://{host}"
                async with sem:
                    status, title = await probe_one(session, url)
                d[scheme] = (status, title)
            results[host] = d

        tasks = [asyncio.create_task(worker(h)) for h in hosts]
        for i in range(0, len(tasks), 1000):
            await asyncio.gather(*tasks[i:i+1000], return_exceptions=True)
    return results

# ============================
# Orchestration
# ============================

async def enumerate_domain(domain: str, args) -> Tuple[Dict[str, HostRecord], Set[str]]:
    all_subs: Set[str] = set()

    vt_key = args.virustotal or os.getenv("VIRUSTOTAL_API_KEY")
    st_key = args.securitytrails or os.getenv("SECURITYTRAILS_API_KEY")

    if args.passive:
        print(f"[*] Passive discovery for {domain} ...")
        subs = await gather_passive(domain, vt_key, st_key)
        print(f"    [+] Passive found {len(subs)}")
        all_subs.update(subs)

    if args.bruteforce:
        words = load_wordlist(Path(args.wordlist) if args.wordlist else None)
        print(f"[*] Brute-forcing {domain} with {len(words)} candidates ...")
        ns = args.nameservers.split(',') if args.nameservers else None
        subs = await brute_force(domain, words, args.dns_concurrency, ns)
        print(f"    [+] Brute force found {len(subs)}")
        all_subs.update(subs)

    all_subs.add(domain)

    # Resolve
    print(f"[*] Resolving {len(all_subs)} hostnames ...")
    resolver = dns.resolver.Resolver()
    if args.nameservers:
        resolver.nameservers = args.nameservers.split(',')
    resolver.lifetime = 3.0
    resolver.timeout = 3.0

    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(args.dns_concurrency)
    records: Dict[str, HostRecord] = {}

    async def resolve_task(h: str):
        async with sem:
            ips, cname = await loop.run_in_executor(None, resolve_hostname, h, resolver)
        records[h] = HostRecord(hostname=h, ips=ips, cname=cname)

    tasks = [asyncio.create_task(resolve_task(h)) for h in sorted(all_subs)]
    for i in range(0, len(tasks), 1000):
        await asyncio.gather(*tasks[i:i+1000], return_exceptions=True)

    if not args.keep_unresolved:
        before = len(records)
        records = {h: rec for h, rec in records.items() if rec.ips}
        print(f"[*] Filter unresolved: {before} -> {len(records)}")

    # Probe
    if args.probe:
        print(f"[*] Probing HTTP/HTTPS on {len(records)} hosts ...")
        probe_res = await probe_http(records.keys(), args.http_concurrency)
        for host, d in probe_res.items():
            rec = records.get(host)
            if not rec:
                continue
            hstat, htitle = d.get("http", (None, None))
            sstat, stitle = d.get("https", (None, None))
            rec.http_status = hstat
            rec.http_title = htitle
            rec.https_status = sstat
            rec.https_title = stitle
            rec.http_url = f"http://{host}" if hstat else None
            rec.https_url = f"https://{host}" if sstat else None

    return records, all_subs


def write_outputs(domain: str, outdir: Path, records: Dict[str, HostRecord], all_subs: Set[str]) -> Tuple[Path, Path, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    raw_path = outdir / f"{safe_filename(domain)}-subdomains-raw-{ts}.txt"
    raw_path.write_text("\n".join(sorted(all_subs)), encoding="utf-8")

    csv_path = outdir / f"{safe_filename(domain)}-hosts-{ts}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["hostname","ips","cname","http_status","https_status","http_title","https_title","http_url","https_url"])
        for host in sorted(records):
            writer.writerow(records[host].to_row())

    json_path = outdir / f"{safe_filename(domain)}-hosts-{ts}.json"
    with json_path.open("w", encoding="utf-8") as f:
        json.dump({h: asdict(rec) for h, rec in records.items()}, f, indent=2)

    print(f"[*] Wrote outputs:\n  - {raw_path}\n  - {csv_path}\n  - {json_path}")
    return raw_path, csv_path, json_path


def urls_for_live(records: Dict[str, HostRecord]) -> List[str]:
    urls: List[str] = []
    for rec in records.values():
        if rec.https_status:
            urls.append(f"https://{rec.hostname}")
        elif rec.http_status:
            urls.append(f"http://{rec.hostname}")
    seen = set()
    out: List[str] = []
    for u in urls:
        if u not in seen:
            out.append(u)
            seen.add(u)
    return out

# ============================
# CLI
# ============================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Subdomain discovery + DNS resolve + HTTP probe")
    p.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    p.add_argument("-o", "--outdir", default="out", help="Output directory (relative to script folder)")
    p.add_argument("--passive", action="store_true", help="Use passive sources")
    p.add_argument("--bruteforce", action="store_true", help="Use DNS brute-force")
    p.add_argument("--wordlist", help="Path to subdomain wordlist")
    p.add_argument("--nameservers", help="Comma-separated nameservers (e.g., 1.1.1.1,8.8.8.8)")
    p.add_argument("--dns-concurrency", type=int, default=100, help="DNS concurrency")
    p.add_argument("--probe", action="store_true", help="Probe HTTP/HTTPS")
    p.add_argument("--http-concurrency", type=int, default=50, help="HTTP concurrency")
    p.add_argument("--keep-unresolved", action="store_true", help="Keep unresolved hosts in outputs")
    p.add_argument("--virustotal", help="VirusTotal API key (overrides env var)")
    p.add_argument("--securitytrails", help="SecurityTrails API key (overrides env var)")
    return p.parse_args()


def normalize_domain(raw: str) -> str:
    raw = raw.strip().lower()
    ext = tldextract.extract(raw)
    root = ext.top_domain_under_public_suffix  # replacement for deprecated registered_domain
    if not root:
        print(f"[!] '{raw}' doesn't look like a valid registrable domain")
        sys.exit(2)
    return root


def main():
    args = parse_args()

    if not (args.passive or args.bruteforce):
        print("[!] Choose at least one discovery method: --passive and/or --bruteforce")
        sys.exit(2)

    script_dir = Path(__file__).resolve().parent
    outdir = (script_dir / args.outdir).resolve()
    domain = normalize_domain(args.domain)

    try:
        records, all_subs = asyncio.run(enumerate_domain(domain, args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)

    _, _, _ = write_outputs(domain, outdir, records, all_subs)

    if args.probe:
        live = urls_for_live(records)
        print(f"[*] Live URLs: {len(live)}")
        for u in live[:20]:
            print(f"    {u}")
        if len(live) > 20:
            print("    ... (see CSV/JSON for full list)")

    print("[*] Done.")


if __name__ == "__main__":
    main()

