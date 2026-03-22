# Armenia Proxy Checker

Automatically finds and verifies **working Armenian IP proxies** every 24 hours.

## How it works

1. Scrapes **10+ sources** (proxy APIs + GitHub live-updated lists)
2. Tests every candidate via `ip-api.com` — confirms exit IP is truly in Armenia 🇦🇲
3. Tries **SOCKS5 → SOCKS4 → HTTP** per proxy and records the working protocol
4. Saves results sorted by latency to `working_armenia_proxies.txt` and `working_armenia_proxies.json`
5. Runs automatically every day at 20:30 UTC via GitHub Actions

## Sources scraped

| Source | Type |
|---|---|
| ProxyScrape API (HTTP/SOCKS4/SOCKS5) | JSON API |
| Geonode API (pages 1–5) | JSON API |
| proxifly (AM country list) | Plain text |
| proxydb.net (HTTP + SOCKS5) | HTML scrape |
| vakhov/fresh-proxy-list (GitHub) | Raw text |
| ErcinDedeoglu/proxies (GitHub) | Raw text |
| proxy4parsing/proxy-list (GitHub) | Raw text |
| Zaeem20/FREE_PROXIES_LIST (GitHub) | Raw text |

## Output format

```
# Armenian Proxies — 2025-01-01 20:30 UTC
# Freshness window: 72h | Mode: COLLECT-ONLY
# Live-verified: 12 | Fresh CIDR-confirmed: 38

# === LIVE-VERIFIED WORKING PROXIES ===

SOCKS5   176.x.x.x:1080       284ms
HTTP     46.x.x.x:8080        491ms
...

# --- Raw (verified) ---
176.x.x.x:1080
46.x.x.x:8080
...

# === ALL FRESH ARMENIAN IPs (unverified) ===

176.x.x.x:1080    # geonode   last_seen: 2025-01-01T20:10:00Z
46.x.x.x:3128     # proxyscrape
...
```

## Run manually

```bash
pip install -r requirements.txt
python check_proxies.py
```

To run a full live test instead of collect-only mode:

```bash
python check_proxies.py   # COLLECT_ONLY unset → runs live TCP+HTTP tests
```

## Test locally from your own network (R)

The included `test_local.R` script re-tests the collected proxies directly from your machine, confirming an Armenian exit IP from your connection in real time.

```bash
Rscript test_local.R
Rscript test_local.R --file working_armenia_proxies.txt --workers 20
```

## Use the proxies on Android

1. Install **Super Proxy** or **NekoBox** from Google Play
2. Copy any `IP:PORT` from `working_armenia_proxies.txt`
3. Add as SOCKS5 or HTTP → tap Start
4. Verify at `iplocation.net`

## Trigger a manual run

Go to **Actions → Armenia Proxy Checker → Run workflow** in your GitHub repo.
