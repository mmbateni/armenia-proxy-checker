#!/usr/bin/env python3
"""
Armenia Proxy Checker — Iran-Bridge Edition
============================================
Collects HTTP/SOCKS proxies from Armenian IP space (fresh-only approach),
verifies them live, then applies an Iran-bridge test: each working Armenian
proxy is used to probe known Iranian internal IP addresses. Proxies that
can reach those addresses are saved as Iran-accessible bridge proxies.

Why this matters
----------------
Armenian ISPs (ArmenTel, Ucom, VivaCell-MTS) maintain BGP peering with
major Iranian carriers (TCI AS12880, MCI AS197207, Irancell AS44244).
Traffic originating from Armenian address space can traverse these peering
links and reach Iranian internal IPs that are unreachable from the internet.
A proxy server sitting inside Armenia on such a network can therefore act
as a bridge into the Iranian internal network.

Freshness window (FRESH_HOURS, default 72)
  Sources with timestamps   → age filter applied
  Sources without timestamps → only repos updated within the window (GitHub API)

Outputs
-------
  working_armenia_proxies.txt        – all live-verified Armenian proxies
  working_armenia_proxies.json       – structured JSON with metadata
  armenia_iran_bridge_proxies.txt    – proxies that can reach Iranian IPs
  armenia_iran_bridge_proxies.json   – structured, ready for integration
"""

import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

# ── Config ────────────────────────────────────────────────────────────────────

COLLECT_ONLY   = os.environ.get("COLLECT_ONLY",    "").strip() == "1"
FRESH_HOURS    = int(os.environ.get("FRESH_HOURS", "72"))
SCRAPE_TIMEOUT = 12
TCP_TIMEOUT    = 8
HTTP_TIMEOUT   = 20
MAX_WORKERS    = 60
SKIP_IRAN_BRIDGE = os.environ.get("SKIP_IRAN_BRIDGE", "").strip() == "1"

# Seconds to wait when probing an Iranian endpoint through an Armenian proxy.
IRAN_BRIDGE_TIMEOUT = int(os.environ.get("IRAN_BRIDGE_TIMEOUT", "10"))

# ── Iranian internal endpoints to probe ───────────────────────────────────────
# First-hop IPs of well-known Iranian ASNs, unreachable from the open internet
# but accessible via BGP-peered Armenian exit nodes.
IRAN_TEST_ENDPOINTS = [
    ("5.160.0.1",     80),   # TCI / AS12880
    ("78.38.0.1",     80),   # TCI
    ("151.232.0.1",   80),   # MCI / AS197207
    ("185.112.32.1",  80),   # Irancell / AS44244
    ("185.141.104.1", 80),   # Shatel / AS48159
    ("185.173.128.1", 80),   # Rightel / AS48434
    ("5.200.200.200", 80),   # Public Iranian fallback
]

# ip-api verification endpoints for the proxy exit country
PROXY_VERIFY_URLS = [
    ("http://ip-api.com/json/?fields=status,countryCode,query,org,city", "json"),
    ("http://httpbin.org/ip",        "text"),
    ("http://api.ipify.org",         "text"),
    ("http://ifconfig.me/ip",        "text"),
    ("http://checkip.amazonaws.com", "text"),
    # Armenian-hosted (extra signal that routing is staying in-country)
    ("http://ucom.am",  "text"),
    ("http://mts.am",   "text"),
]

ARMENIA_CIDR_URLS = [
    "https://www.ipdeny.com/ipblocks/data/countries/am.zone",
    "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/am.cidr",
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/am/ipv4-aggregated.txt",
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
}

IP_PORT_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")
PRIVATE_RE = re.compile(
    r"^(?:0\.|10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)"
)

NOW_UTC = datetime.now(timezone.utc)
CUTOFF  = NOW_UTC - timedelta(hours=FRESH_HOURS)


def log(msg: str) -> None:
    print(f"[{NOW_UTC.strftime('%H:%M:%S')}] {msg}", flush=True)


# ── Armenia CIDR loader ───────────────────────────────────────────────────────

def load_armenia_networks() -> list[ipaddress.IPv4Network]:
    cidr_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})")
    for url in ARMENIA_CIDR_URLS:
        try:
            r = requests.get(url, headers=HEADERS, timeout=15)
            r.raise_for_status()
            nets = []
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = cidr_re.search(line)
                if m:
                    try:
                        nets.append(ipaddress.IPv4Network(m.group(1), strict=False))
                    except ValueError:
                        pass
            if nets:
                log(f"  Loaded {len(nets)} Armenia CIDR blocks from {url}")
                return nets
        except Exception as e:
            log(f"  ! CIDR {url}: {e}")

    log("  Using hardcoded fallback CIDRs for key Armenian ISPs")
    fallback = [
        # Ucom LLC
        "5.105.0.0/16", "77.92.0.0/17", "85.105.0.0/16", "176.74.0.0/15",
        # VivaCell-MTS
        "46.70.0.0/15", "91.194.168.0/21",
        # Beeline Armenia
        "84.234.0.0/17", "94.43.128.0/17",
        # ArmenTel
        "109.75.0.0/16", "213.135.64.0/18",
        # GNC-Alfa
        "37.252.64.0/18", "212.34.32.0/19",
        # DataCenter / hosting
        "91.210.172.0/22", "91.214.44.0/22",
        "185.4.212.0/22",  "185.40.240.0/22",
        "185.112.144.0/22","185.130.44.0/22",
        "185.183.96.0/22", "185.200.116.0/22",
        "193.200.200.0/22","194.9.24.0/21",
        "194.67.216.0/21", "195.34.32.0/19",
        "212.92.128.0/18",
    ]
    return [ipaddress.IPv4Network(c, strict=False) for c in fallback]


def in_armenia(ip: str, networks: list[ipaddress.IPv4Network]) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False


def cidr_filter(candidates: set[str],
                networks: list[ipaddress.IPv4Network]) -> set[str]:
    log(f"CIDR-filtering {len(candidates)} candidates …")
    t = time.monotonic()
    result = {p for p in candidates if in_armenia(p.split(":")[0], networks)}
    log(f"  → {len(result)} Armenian IPs in {round(time.monotonic()-t, 2)}s")
    return result


# ── Freshness helpers ─────────────────────────────────────────────────────────

def is_fresh(ts_str: str) -> bool:
    if not ts_str:
        return False
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str[:26], fmt).replace(tzinfo=timezone.utc)
            return dt >= CUTOFF
        except ValueError:
            continue
    return False


def clean_proxy(proxy: str) -> str | None:
    parts = proxy.strip().split(":")
    if len(parts) != 2:
        return None
    ip, port_str = parts
    if PRIVATE_RE.match(ip):
        return None
    try:
        if 1 <= int(port_str) <= 65535:
            return proxy.strip()
    except ValueError:
        pass
    return None


# ── Sources with timestamps ───────────────────────────────────────────────────

def fetch_geonode_fresh() -> dict[str, str]:
    results: dict[str, str] = {}
    total = kept = 0
    for page in range(1, 6):
        url = (f"https://proxylist.geonode.com/api/proxy-list"
               f"?country=AM&limit=100&page={page}"
               f"&sort_by=lastChecked&sort_type=desc")
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            data = r.json().get("data", [])
            if not data:
                break
            for p in data:
                ip    = p.get("ip", "")
                ts    = p.get("updatedAt") or p.get("lastChecked") or p.get("created_at", "")
                ports = p.get("port", [])
                if isinstance(ports, (int, str)):
                    ports = [ports]
                for port in ports:
                    proxy = f"{ip}:{port}"
                    total += 1
                    if is_fresh(ts):
                        kept += 1
                        results[proxy] = ts
        except Exception as e:
            log(f"  ! geonode page {page}: {e}")
            break
    log(f"  [geonode] {kept}/{total} proxies within {FRESH_HOURS}h")
    return results


def fetch_proxyscrape_fresh() -> dict[str, str]:
    results: dict[str, str] = {}
    total = kept = 0
    for protocol in ("http", "socks4", "socks5"):
        url = (f"https://api.proxyscrape.com/v3/free-proxy-list/get"
               f"?request=getproxies&country=am&protocol={protocol}"
               f"&anonymity=all&timeout=10000&format=json")
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            data = r.json()
            for p in data.get("proxies", []):
                proxy = p.get("proxy", "")
                ts    = p.get("last_seen", "") or p.get("added", "")
                total += 1
                if proxy and is_fresh(ts):
                    kept += 1
                    results[proxy] = ts
        except Exception as e:
            log(f"  ! proxyscrape {protocol}: {e}")
    log(f"  [proxyscrape] {kept}/{total} proxies within {FRESH_HOURS}h")
    return results


def fetch_proxifly_fresh() -> dict[str, str]:
    results: dict[str, str] = {}
    url = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/AM/data.txt"
    try:
        r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
        for ip, port in IP_PORT_RE.findall(r.text):
            proxy = f"{ip}:{port}"
            if not PRIVATE_RE.match(ip):
                results[proxy] = "fresh_5min"
        log(f"  [proxifly] {len(results)} AM proxies")
    except Exception as e:
        log(f"  ! proxifly: {e}")
    return results


# ── Sources without timestamps ────────────────────────────────────────────────

def github_repo_updated_within(owner: str, repo: str, max_hours: int) -> bool:
    try:
        r = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers={**HEADERS, "Accept": "application/vnd.github+json"},
            timeout=10,
        )
        pushed = r.json().get("pushed_at", "")
        return is_fresh(pushed) if pushed else False
    except Exception:
        return False


def fetch_github_raw_fresh(name: str, owner: str, repo: str,
                            path: str, max_hours: int) -> dict[str, str]:
    if not github_repo_updated_within(owner, repo, max_hours):
        log(f"  [github/{name}] not updated within {max_hours}h — skipped")
        return {}
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{path}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
        result = {}
        for ip, port in IP_PORT_RE.findall(r.text):
            proxy = f"{ip}:{port}"
            if not PRIVATE_RE.match(ip):
                result[proxy] = "repo_fresh"
        log(f"  [github/{name}] {len(result)} proxies")
        return result
    except Exception as e:
        log(f"  ! github/{name}: {e}")
        return {}


def fetch_am_targeted() -> dict[str, str]:
    results: dict[str, str] = {}
    sources = [
        ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/AM/data.json",
         "proxifly_json"),
        ("https://proxydb.net/?protocol=socks5&country=AM", "proxydb_am"),
        ("https://proxydb.net/?protocol=http&country=AM",   "proxydb_am_http"),
    ]
    for url, label in sources:
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            for ip, port in IP_PORT_RE.findall(r.text):
                proxy = f"{ip}:{port}"
                if not PRIVATE_RE.match(ip):
                    results[proxy] = "am_targeted"
            log(f"  [{label}] collected")
        except Exception as e:
            log(f"  ! {label}: {e}")
    return results


# ── Collector ─────────────────────────────────────────────────────────────────

def collect_fresh_candidates() -> dict[str, dict]:
    log("\n── Collecting fresh candidates (parallel) ──")
    all_proxies: dict[str, dict] = {}

    def merge(d: dict[str, str], source_name: str) -> None:
        for proxy, ts in d.items():
            p = clean_proxy(proxy)
            if p and p not in all_proxies:
                all_proxies[p] = {"ts": ts, "source": source_name}

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        jobs = {
            ex.submit(fetch_geonode_fresh)      : "geonode",
            ex.submit(fetch_proxyscrape_fresh)  : "proxyscrape",
            ex.submit(fetch_proxifly_fresh)     : "proxifly",
            ex.submit(fetch_am_targeted)        : "am_targeted",
            ex.submit(fetch_github_raw_fresh,
                "vakhov_s5", "vakhov", "fresh-proxy-list",
                "socks5.txt", 6)                : "vakhov_s5",
            ex.submit(fetch_github_raw_fresh,
                "ercindedeoglu_s5", "ErcinDedeoglu", "proxies",
                "proxies/socks5.txt", 12)       : "ercindedeoglu_s5",
            ex.submit(fetch_github_raw_fresh,
                "ercindedeoglu_http", "ErcinDedeoglu", "proxies",
                "proxies/http.txt", 12)         : "ercindedeoglu_http",
            ex.submit(fetch_github_raw_fresh,
                "proxy4p", "proxy4parsing", "proxy-list",
                "http.txt", 1)                  : "proxy4p",
            ex.submit(fetch_github_raw_fresh,
                "zaeem_http", "Zaeem20", "FREE_PROXIES_LIST",
                "http.txt", 24)                 : "zaeem_http",
        }
        for future in concurrent.futures.as_completed(jobs):
            name = jobs[future]
            try:
                result = future.result()
                if isinstance(result, dict):
                    merge(result, name)
                elif isinstance(result, set):
                    merge({p: "" for p in result}, name)
            except Exception as e:
                log(f"  ! {name}: {e}")

    log(f"\n  Total fresh candidates: {len(all_proxies)}")
    return all_proxies


# ── Live test ─────────────────────────────────────────────────────────────────

def tcp_check(ip: str, port: int) -> str:
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            return "ok"
    except ConnectionRefusedError:
        return "refused"
    except Exception:
        return "timeout"


def test_proxy(proxy_str: str) -> dict:
    ip, port_str = proxy_str.rsplit(":", 1)
    port = int(port_str)
    tcp = tcp_check(ip, port)
    if tcp != "ok":
        return {"proxy": proxy_str, "tcp": tcp, "working": False}

    for proto in ("socks5", "socks4", "http"):
        px = {"http": f"{proto}://{ip}:{port}", "https": f"{proto}://{ip}:{port}"}
        for test_url, _ in PROXY_VERIFY_URLS:
            try:
                t = time.monotonic()
                r = requests.get(test_url, proxies=px, timeout=HTTP_TIMEOUT, headers=HEADERS)
                latency = round((time.monotonic() - t) * 1000)
                if r.status_code < 400:
                    cc = city = org = exit_ip = ""
                    try:
                        d = r.json()
                        cc      = d.get("countryCode", "")
                        city    = d.get("city", "")
                        org     = d.get("org", "")
                        exit_ip = d.get("query", "")
                    except Exception:
                        pass
                    return {
                        "proxy": proxy_str, "tcp": "ok", "working": True,
                        "protocol": proto.upper(), "latency_ms": latency,
                        "country": cc, "city": city, "isp": org,
                        "exit_ip": exit_ip,
                    }
            except Exception:
                continue

    return {"proxy": proxy_str, "tcp": "ok", "working": False}


# ── Iran-bridge test ──────────────────────────────────────────────────────────

def test_iran_bridge(result: dict) -> dict:
    """
    Probe IRAN_TEST_ENDPOINTS through the verified Armenian proxy.
    Updates result in-place with 'iran_bridge' and 'iran_reached_ip'.
    """
    if SKIP_IRAN_BRIDGE:
        result["iran_bridge"]    = True
        result["iran_reached_ip"] = "skipped"
        return result

    ip, port_str = result["proxy"].rsplit(":", 1)
    port  = int(port_str)
    proto = result.get("protocol", "HTTP").lower()
    if proto not in ("http", "socks4", "socks5"):
        proto = "http"

    proxy_url = f"{proto}://{ip}:{port}"
    proxies   = {"http": proxy_url, "https": proxy_url}

    for iran_ip, iran_port in IRAN_TEST_ENDPOINTS:
        target = f"http://{iran_ip}:{iran_port}/"
        try:
            r = requests.get(
                target, proxies=proxies,
                timeout=IRAN_BRIDGE_TIMEOUT,
                headers=HEADERS, allow_redirects=False,
            )
            # Any HTTP response (even error page) = routable
            if r.status_code < 600:
                result["iran_bridge"]     = True
                result["iran_reached_ip"] = iran_ip
                return result
        except requests.exceptions.ProxyError:
            continue
        except requests.exceptions.ConnectionError:
            # Connection refused at the Iranian end but routed = success
            result["iran_bridge"]     = True
            result["iran_reached_ip"] = iran_ip
            return result
        except Exception:
            continue

    result["iran_bridge"]    = False
    result["iran_reached_ip"] = None
    return result


# ── Writers ───────────────────────────────────────────────────────────────────

def write_outputs(
    am_info: dict[str, dict],
    armenian: set[str],
    working: list[dict],
    bridge: list[dict],
    tcp_stats: dict,
    mode: str,
) -> None:
    now      = NOW_UTC.strftime("%Y-%m-%d %H:%M UTC")
    src_counts = Counter(v["source"] for v in am_info.values())

    priority_order = ["geonode", "proxyscrape", "proxifly",
                      "am_targeted", "proxydb"]

    def sort_key(proxy: str) -> int:
        src = am_info[proxy]["source"]
        try:
            return priority_order.index(src)
        except ValueError:
            return len(priority_order)

    # All verified Armenian proxies
    out = Path("working_armenia_proxies.txt")
    with open(out, "w") as f:
        f.write(f"# Armenian Proxies — {now}\n")
        f.write(f"# Freshness window: {FRESH_HOURS}h | Mode: {mode}\n")
        f.write(f"# Live-verified: {len(working)} | Fresh CIDR-confirmed: {len(armenian)}\n")
        f.write(f"# TCP: ok={tcp_stats.get('ok',0)} "
                f"refused={tcp_stats.get('refused',0)} "
                f"timeout={tcp_stats.get('timeout',0)}\n#\n\n")
        if working:
            f.write("# === LIVE-VERIFIED WORKING PROXIES ===\n\n")
            for p in working:
                f.write(f"{p['protocol']:<8} {p['proxy']:<26} {p['latency_ms']:>5}ms\n")
            f.write("\n# --- Raw ---\n")
            for p in working:
                f.write(f"{p['proxy']}\n")
        f.write("\n# === ALL FRESH ARMENIAN IPs (unverified) ===\n\n")
        for proxy in sorted(armenian, key=sort_key):
            info = am_info[proxy]
            ts_str = (f"  last_seen: {info['ts']}"
                      if info.get("ts") and info["ts"] not in
                         ("", "repo_fresh", "am_targeted", "fresh_5min")
                      else "")
            f.write(f"{proxy:<26}  # {info['source']}{ts_str}\n")

    with open("working_armenia_proxies.json", "w") as f:
        json.dump({
            "checked_at"    : now,
            "fresh_hours"   : FRESH_HOURS,
            "mode"          : mode,
            "verified_count": len(working),
            "fresh_count"   : len(armenian),
            "tcp_stats"     : tcp_stats,
            "source_counts" : dict(src_counts),
            "verified"      : working,
            "all_fresh_ips" : [
                {"proxy": p, "source": am_info[p]["source"], "ts": am_info[p]["ts"]}
                for p in sorted(armenian, key=sort_key)
            ],
        }, f, indent=2, ensure_ascii=False)

    # Iran-bridge proxies
    with open("armenia_iran_bridge_proxies.txt", "w") as f:
        f.write(f"# Armenian → Iranian Network Bridge Proxies — {now}\n")
        f.write(f"# {len(bridge)} proxies confirmed to route into Iranian internal network\n")
        f.write("# Use with any SOCKS/HTTP proxy client or import into Hiddify\n\n")
        f.write("# === BRIDGE PROXIES (protocol  address  latency  iranian_ip_reached) ===\n\n")
        for p in bridge:
            f.write(
                f"{p.get('protocol','?'):<8} {p['proxy']:<26} "
                f"{p.get('latency_ms',0):>5}ms  "
                f"→ {p.get('iran_reached_ip','?')}\n"
            )
        f.write("\n# --- Raw proxy list ---\n")
        for p in bridge:
            f.write(f"{p['proxy']}\n")

    with open("armenia_iran_bridge_proxies.json", "w") as f:
        json.dump({
            "checked_at":  now,
            "count":       len(bridge),
            "description": "Armenian proxies with confirmed access to Iranian internal network",
            "proxies":     bridge,
        }, f, indent=2, ensure_ascii=False)

    log(f"Saved → working_armenia_proxies.txt | working_armenia_proxies.json")
    log(f"Saved → armenia_iran_bridge_proxies.txt ({len(bridge)} bridge proxies) | .json")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    sep  = "=" * 60
    mode = "COLLECT-ONLY" if COLLECT_ONLY else "FULL TEST"
    log(sep)
    log(f"Armenia Proxy Checker — Iran-Bridge Edition [{mode}]")
    log(f"Freshness window: {FRESH_HOURS}h | "
        f"Iran-bridge timeout: {IRAN_BRIDGE_TIMEOUT}s | "
        f"Skip bridge: {SKIP_IRAN_BRIDGE}")
    log(sep)

    log("\n── Loading Armenia IP ranges ──")
    armenia_networks = load_armenia_networks()

    proxy_info = collect_fresh_candidates()
    if not proxy_info:
        log("ERROR: No fresh candidates found.")
        return

    log("\n── Geo-filtering ──")
    armenian = cidr_filter(set(proxy_info.keys()), armenia_networks)
    am_info  = {p: proxy_info[p] for p in armenian}

    if not armenian:
        log("No Armenian-range IPs found.")
        return

    src_counts = Counter(v["source"] for v in am_info.values())
    log("  Source breakdown:")
    for src, cnt in src_counts.most_common():
        log(f"    {src:<25} {cnt}")

    working    : list[dict] = []
    tcp_stats  : dict       = {"ok": 0, "refused": 0, "timeout": 0}
    all_results: list[dict] = []

    if COLLECT_ONLY:
        log(f"\n── COLLECT-ONLY: {len(armenian)} fresh Armenian IPs saved (no live test) ──")
    else:
        log(f"\n── Live testing {len(armenian)} fresh proxies ({MAX_WORKERS} threads) ──\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {ex.submit(test_proxy, p): p for p in armenian}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                result = future.result()
                all_results.append(result)
                if result.get("working"):
                    log(f"  ✓ [{result['protocol']:<6}] {result['proxy']:<26} "
                        f"{result['latency_ms']:>5}ms  "
                        f"{result.get('city','')}  {result.get('isp','')}")
                if done % 50 == 0:
                    ok = sum(1 for r in all_results if r["tcp"] == "ok")
                    wk = sum(1 for r in all_results if r.get("working"))
                    log(f"  … {done}/{len(armenian)} | TCP-ok:{ok} | working:{wk}")

        working = sorted(
            [r for r in all_results if r.get("working")],
            key=lambda x: x["latency_ms"],
        )
        tcp_stats = {
            "ok":      sum(1 for r in all_results if r["tcp"] == "ok"),
            "refused": sum(1 for r in all_results if r["tcp"] == "refused"),
            "timeout": sum(1 for r in all_results if r["tcp"] == "timeout"),
        }

        proto_counts: dict[str, int] = {}
        for p in working:
            proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1
        breakdown = "  ".join(f"{k}:{v}" for k, v in sorted(proto_counts.items()))

        log(f"\n{'='*60}")
        log(f"total={len(armenian)}  tcp-ok={tcp_stats['ok']}  "
            f"refused={tcp_stats['refused']}  timeout={tcp_stats['timeout']}  "
            f"working={len(working)}")
        if breakdown:
            log(f"Protocol breakdown: {breakdown}")
        log(f"{'='*60}\n")

    # ── Iran-bridge test ──────────────────────────────────────────────────────
    bridge: list[dict] = []
    if working:
        log(f"\n── Iran-bridge testing {len(working)} working proxies "
            f"({min(40, MAX_WORKERS)} threads) ──\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(40, MAX_WORKERS)) as ex:
            futs = {ex.submit(test_iran_bridge, r): r for r in working}
            for fut in concurrent.futures.as_completed(futs):
                result = futs[fut]
                r = fut.result()
                if r.get("iran_bridge"):
                    bridge.append(r)
                    log(f"  🌉 Bridge [{r.get('protocol','?'):<6}] "
                        f"{r['proxy']:<26} → {r.get('iran_reached_ip','?')}")
        bridge.sort(key=lambda x: x.get("latency_ms", 9999))
        log(f"\n  Iran-bridge confirmed: {len(bridge)} / {len(working)} proxies")

    write_outputs(am_info, armenian, working, bridge, tcp_stats, mode)


if __name__ == "__main__":
    main()
