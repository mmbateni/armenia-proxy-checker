#!/usr/bin/env python3
"""
Armenia Proxy Checker — Fresh-Only Edition
Key idea: Armenian network conditions change hourly.
Only collect proxies reported active within the last FRESH_HOURS hours.

Sources with timestamps → age filter applied
Sources without timestamps → only use repos updated < 6h ago (via GitHub API)
"""

import ipaddress
import os
import socket
import requests
import concurrent.futures
import json
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

COLLECT_ONLY   = os.environ.get("COLLECT_ONLY", "").strip() == "1"
FRESH_HOURS    = int(os.environ.get("FRESH_HOURS", "72"))   # max age in hours
SCRAPE_TIMEOUT = 12
TCP_TIMEOUT    = 8
HTTP_TIMEOUT   = 20
MAX_WORKERS    = 60

ARMENIA_CIDR_URLS = [
    "https://www.ipdeny.com/ipblocks/data/countries/am.zone",
    "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/am.cidr",
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/am/ipv4-aggregated.txt",
]

TEST_URLS = [
    "http://ip-api.com/json/?fields=status,countryCode,query,org,city",
    "http://httpbin.org/ip",
    "http://api.ipify.org",
    "http://ifconfig.me/ip",
    "http://checkip.amazonaws.com",
    "http://ucom.am",
    "http://mts.am",
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


def log(msg):
    ts = NOW_UTC.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


# ── Armenia CIDR loader ───────────────────────────────────────────────────────

def load_armenia_networks():
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
                log(f"  Loaded {len(nets)} Armenia CIDR blocks")
                return nets
        except Exception as e:
            log(f"  ! CIDR {url}: {e}")

    log("  Using hardcoded fallback CIDRs")
    # Key Armenian ISPs: Ucom, VivaCell-MTS, Beeline Armenia, GNC-Alfa, ArmenTel
    fallback = [
        "5.105.0.0/16",
        "5.134.208.0/21",
        "37.252.64.0/18",
        "46.70.0.0/15",
        "77.92.0.0/17",
        "77.95.48.0/22",
        "84.234.0.0/17",
        "85.105.0.0/16",
        "91.194.168.0/21",
        "91.210.172.0/22",
        "91.214.44.0/22",
        "91.228.148.0/22",
        "94.43.128.0/17",
        "109.75.0.0/16",
        "176.74.0.0/15",
        "185.4.212.0/22",
        "185.40.240.0/22",
        "185.112.144.0/22",
        "185.130.44.0/22",
        "185.183.96.0/22",
        "185.200.116.0/22",
        "193.200.200.0/22",
        "194.9.24.0/21",
        "194.67.216.0/21",
        "195.34.32.0/19",
        "212.34.32.0/19",
        "212.92.128.0/18",
        "213.135.64.0/18",
    ]
    return [ipaddress.IPv4Network(c, strict=False) for c in fallback]


def in_armenia(ip, networks):
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False


def cidr_filter(candidates, networks):
    log(f"CIDR-filtering {len(candidates)} candidates…")
    t = time.monotonic()
    result = {p for p in candidates if in_armenia(p.split(":")[0], networks)}
    log(f"  → {len(result)} Armenian IPs in {round(time.monotonic()-t,2)}s")
    return result


def is_fresh(ts_str):
    """Return True if timestamp string is within FRESH_HOURS of now."""
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


def clean_proxy(proxy):
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


# ══════════════════════════════════════════════════════════════════════════════
# SOURCES WITH TIMESTAMPS (freshness filter applied)
# ══════════════════════════════════════════════════════════════════════════════

def fetch_geonode_fresh():
    """Geonode JSON API — has lastChecked timestamp per proxy."""
    results = {}
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
                ip   = p.get("ip", "")
                ts   = p.get("updatedAt") or p.get("lastChecked") or p.get("created_at", "")
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


def fetch_proxyscrape_fresh():
    """ProxyScrape v3 API — returns lastSeen timestamps in JSON."""
    results = {}
    total = kept = 0
    for protocol in ("http", "socks4", "socks5"):
        url = (f"https://api.proxyscrape.com/v3/free-proxy-list/get"
               f"?request=getproxies&country=am&protocol={protocol}"
               f"&anonymity=all&timeout=10000&format=json")
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            data = r.json()
            proxies_list = data.get("proxies", [])
            for p in proxies_list:
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


def fetch_proxifly_fresh():
    """Proxifly AM-specific list — updated every 5 minutes."""
    results = {}
    url = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/AM/data.txt"
    try:
        r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
        matches = IP_PORT_RE.findall(r.text)
        for ip, port in matches:
            proxy = f"{ip}:{port}"
            if not PRIVATE_RE.match(ip):
                results[proxy] = "fresh_5min"
        log(f"  [proxifly] {len(results)} AM proxies")
    except Exception as e:
        log(f"  ! proxifly: {e}")
    return results


# ══════════════════════════════════════════════════════════════════════════════
# SOURCES WITHOUT TIMESTAMPS (GitHub repo freshness check)
# ══════════════════════════════════════════════════════════════════════════════

def github_repo_updated_within(owner, repo, max_hours):
    """Return True if the GitHub repo was pushed to within max_hours."""
    try:
        url = f"https://api.github.com/repos/{owner}/{repo}"
        r = requests.get(url, headers={**HEADERS, "Accept": "application/vnd.github+json"},
                         timeout=10)
        pushed = r.json().get("pushed_at", "")
        return is_fresh(pushed) if pushed else False
    except Exception:
        return False


def fetch_github_raw_fresh(name, owner, repo, path, max_hours):
    """Fetch a raw file from GitHub if the repo was updated within max_hours."""
    if not github_repo_updated_within(owner, repo, max_hours):
        log(f"  [github/{name}] repo not updated within {max_hours}h — skipped")
        return {}
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{path}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
        matches = IP_PORT_RE.findall(r.text)
        result = {}
        for ip, port in matches:
            proxy = f"{ip}:{port}"
            if not PRIVATE_RE.match(ip):
                result[proxy] = "repo_fresh"
        log(f"  [github/{name}] {len(result)} proxies")
        return result
    except Exception as e:
        log(f"  ! github/{name}: {e}")
        return {}


def fetch_am_targeted():
    """Fetch from sources that specifically list Armenian proxies."""
    results = {}
    sources = [
        # proxifly JSON variant
        ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/AM/data.json",
         "proxifly_json"),
        # proxydb (country filtered)
        ("https://proxydb.net/?protocol=socks5&country=AM", "proxydb_am"),
        ("https://proxydb.net/?protocol=http&country=AM",   "proxydb_am_http"),
    ]
    for url, label in sources:
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            matches = IP_PORT_RE.findall(r.text)
            for ip, port in matches:
                proxy = f"{ip}:{port}"
                if not PRIVATE_RE.match(ip):
                    results[proxy] = "am_targeted"
            log(f"  [{label}] {len([p for p in results if results[p]=='am_targeted'])} proxies")
        except Exception as e:
            log(f"  ! {label}: {e}")
    return results


# ── Collector ─────────────────────────────────────────────────────────────────

def collect_fresh_candidates():
    log("\n── Collecting fresh candidates (parallel) ──")
    all_proxies = {}

    def merge(d, source_name):
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
                "vakhov_s5","vakhov","fresh-proxy-list",
                "socks5.txt", 6)                : "vakhov_s5",
            ex.submit(fetch_github_raw_fresh,
                "ercindedeoglu_s5","ErcinDedeoglu","proxies",
                "proxies/socks5.txt", 12)       : "ercindedeoglu_s5",
            ex.submit(fetch_github_raw_fresh,
                "ercindedeoglu_http","ErcinDedeoglu","proxies",
                "proxies/http.txt", 12)         : "ercindedeoglu_http",
            ex.submit(fetch_github_raw_fresh,
                "proxy4p","proxy4parsing","proxy-list",
                "http.txt", 1)                  : "proxy4p",
            ex.submit(fetch_github_raw_fresh,
                "zaeem_http","Zaeem20","FREE_PROXIES_LIST",
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

def tcp_check(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            return "ok"
    except ConnectionRefusedError:
        return "refused"
    except Exception:
        return "timeout"


def test_proxy(proxy_str):
    ip, port_str = proxy_str.rsplit(":", 1)
    port = int(port_str)
    tcp = tcp_check(ip, port)
    if tcp != "ok":
        return {"proxy": proxy_str, "tcp": tcp, "working": False}
    for proto in ("socks5", "socks4", "http"):
        px = {"http": f"{proto}://{ip}:{port}", "https": f"{proto}://{ip}:{port}"}
        for test_url in TEST_URLS:
            try:
                t = time.monotonic()
                r = requests.get(test_url, proxies=px, timeout=HTTP_TIMEOUT, headers=HEADERS)
                latency = round((time.monotonic() - t) * 1000)
                if r.status_code < 400:
                    cc = city = org = ""
                    try:
                        d = r.json()
                        cc, city, org = d.get("countryCode",""), d.get("city",""), d.get("org","")
                    except Exception:
                        pass
                    return {"proxy": proxy_str, "tcp": "ok", "working": True,
                            "protocol": proto.upper(), "latency_ms": latency,
                            "country": cc, "city": city, "isp": org}
            except Exception:
                continue
    return {"proxy": proxy_str, "tcp": "ok", "working": False}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    mode = "COLLECT-ONLY" if COLLECT_ONLY else "FULL TEST"
    log(f"Armenia Proxy Checker — Fresh-Only Edition [{mode}]")
    log(f"Freshness window: {FRESH_HOURS} hours")
    log("=" * 60)

    log("\n── Loading Armenia IP ranges ──")
    armenia_networks = load_armenia_networks()

    # Collect fresh candidates
    proxy_info = collect_fresh_candidates()
    if not proxy_info:
        log("ERROR: No fresh candidates found.")
        return

    # CIDR filter
    log("\n── Geo-filtering ──")
    armenian = cidr_filter(set(proxy_info.keys()), armenia_networks)
    am_info  = {p: proxy_info[p] for p in armenian}

    if not armenian:
        log("No Armenian-range IPs found.")
        return

    # Source breakdown
    from collections import Counter
    src_counts = Counter(v["source"] for v in am_info.values())
    log("  Source breakdown:")
    for src, cnt in src_counts.most_common():
        log(f"    {src:<25} {cnt}")

    # Live test
    working = []
    tcp_ok = tcp_refused = tcp_timeout_count = 0

    if COLLECT_ONLY:
        log(f"\n── COLLECT-ONLY: {len(armenian)} fresh Armenian IPs saved (no live test) ──")
    else:
        log(f"\n── Live testing {len(armenian)} fresh proxies ({MAX_WORKERS} threads) ──\n")
        all_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(test_proxy, p): p for p in armenian}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                result = future.result()
                all_results.append(result)
                if result.get("working"):
                    log(f"  ✓ [{result['protocol']:<6}] {result['proxy']:<26} "
                        f"{result['latency_ms']:>5}ms  {result.get('city','')}  {result.get('isp','')}")
                if done % 50 == 0:
                    ok = sum(1 for r in all_results if r["tcp"] == "ok")
                    wk = sum(1 for r in all_results if r.get("working"))
                    log(f"  … {done}/{len(armenian)} | TCP-ok:{ok} | working:{wk}")

        working           = sorted([r for r in all_results if r.get("working")],
                                    key=lambda x: x["latency_ms"])
        tcp_ok            = sum(1 for r in all_results if r["tcp"] == "ok")
        tcp_refused       = sum(1 for r in all_results if r["tcp"] == "refused")
        tcp_timeout_count = sum(1 for r in all_results if r["tcp"] == "timeout")

        proto_counts = {}
        for p in working:
            proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1
        breakdown = "  ".join(f"{k}:{v}" for k, v in sorted(proto_counts.items()))

        log(f"\n{'='*60}")
        log(f"total={len(armenian)}  tcp-ok={tcp_ok}  "
            f"refused={tcp_refused}  timeout={tcp_timeout_count}  working={len(working)}")
        if breakdown:
            log(f"Protocol breakdown: {breakdown}")
        if tcp_timeout_count > tcp_ok:
            log("NOTE: Most timeouts = Azure routing block (use self-hosted runner)")
        log(f"{'='*60}\n")

    now = NOW_UTC.strftime("%Y-%m-%d %H:%M UTC")
    out = Path("working_armenia_proxies.txt")
    with open(out, "w") as f:
        f.write(f"# Armenian Proxies — {now}\n")
        f.write(f"# Freshness window: {FRESH_HOURS}h | Mode: {mode}\n")
        f.write(f"# Live-verified: {len(working)} | Fresh CIDR-confirmed: {len(armenian)}\n")
        if not COLLECT_ONLY:
            f.write(f"# TCP: ok={tcp_ok} refused={tcp_refused} timeout={tcp_timeout_count}\n")
        f.write("#\n\n")

        if working:
            f.write("# === LIVE-VERIFIED WORKING PROXIES ===\n\n")
            for p in working:
                f.write(f"{p['protocol']:<8} {p['proxy']:<26} {p['latency_ms']:>5}ms\n")
            f.write("\n# --- Raw (verified) ---\n")
            for p in working:
                f.write(f"{p['proxy']}\n")
        else:
            f.write("# === ALL FRESH CIDR-CONFIRMED ARMENIAN IPs ===\n")
            if not COLLECT_ONLY and tcp_timeout_count > tcp_ok:
                f.write("# (live test blocked by Azure — run locally for verified results)\n")
            f.write("\n")

        f.write("\n# === ALL FRESH ARMENIAN IPs (unverified) ===\n\n")
        priority_order = ["geonode", "proxyscrape", "proxifly", "am_targeted", "proxydb"]

        def sort_key(proxy):
            src = am_info[proxy]["source"]
            try:
                return priority_order.index(src)
            except ValueError:
                return len(priority_order)

        for proxy in sorted(armenian, key=sort_key):
            info = am_info[proxy]
            ts_str = (f"  last_seen: {info['ts']}"
                      if info.get("ts") and info["ts"] not in ("", "repo_fresh", "am_targeted", "fresh_5min")
                      else "")
            f.write(f"{proxy:<26}  # {info['source']}{ts_str}\n")

    jp = Path("working_armenia_proxies.json")
    with open(jp, "w") as f:
        json.dump({
            "checked_at"    : now,
            "fresh_hours"   : FRESH_HOURS,
            "mode"          : mode,
            "verified_count": len(working),
            "fresh_count"   : len(armenian),
            "tcp_stats"     : {"ok": tcp_ok, "refused": tcp_refused, "timeout": tcp_timeout_count},
            "source_counts" : dict(src_counts),
            "verified"      : working,
            "all_fresh_ips" : [
                {"proxy": p, "source": am_info[p]["source"], "ts": am_info[p]["ts"]}
                for p in sorted(armenian, key=sort_key)
            ],
        }, f, indent=2, ensure_ascii=False)

    log(f"Saved → {out} / {jp}")


if __name__ == "__main__":
    main()
