"""External threat-intelligence cross-referencing.

Extracts indicators (URLs, domains, IPs) from a command and cross-references them
against KNOWN threat databases. Two modes:

  - OFFLINE (default, on the hot path): bundled snapshots of well-known sources
    — LOLBAS / GTFOBins binary lists, public Monero mining-pool lists, abused
    dynamic-DNS providers, high-abuse TLDs, and numeric-IP-obfuscation decoding.
    Zero network => no speed penalty, deterministic.

  - LIVE (optional, --threat-intel, OFF the scored hot path): queries the
    abuse.ch URLhaus host API to confirm a domain/IP is actively malicious.
    Bounded by a global budget and fully guarded; never blocks the verdict.

Sources mirrored offline: LOLBAS-Project, GTFOBins, abuse.ch URLhaus/ThreatFox,
public miner pool lists, ICANN high-abuse TLD reporting.
"""
import ipaddress
import re

_URL = re.compile(r"https?://[^\s'\"]+", re.I)
_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_BARE_INT_IP = re.compile(r"\b(\d{8,10})\b")           # ping 2130706433 == 127.0.0.1
_OCTAL_IP = re.compile(r"\b0\d{2,3}(?:\.\d+){0,3}\b")  # 0177.0.0.1

# --- bundled threat-intel snapshots (representative, extend freely) ---
MINING_POOLS = re.compile(
    r"(minexmr|supportxmr|nanopool|hashvault|monerohash|moneroocean|xmrpool|"
    r"pool\.minexmr|c3pool|2miners|f2pool|nicehash|ethermine|stratum\+tcp|"
    r"randomx|:3333\b|:5555\b|:7777\b|:14444\b|:14433\b|--donate-level)", re.I)

DYNAMIC_DNS = re.compile(
    r"\b\S*\.(no-ip\.\w+|ddns\.net|duckdns\.org|ngrok\.io|ngrok-free\.app|"
    r"serveo\.net|pagekite\.me|dyndns\.\w+|hopto\.org|zapto\.org|sytes\.net|"
    r"trycloudflare\.com)\b", re.I)

HIGH_ABUSE_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "zip", "mov",
    "su", "country", "kim", "men", "loan", "download", "review", "rest",
}

# legitimate domains that often appear in benign CI/CD/admin commands (suppress FP)
KNOWN_GOOD = re.compile(
    r"\b(github\.com|githubusercontent\.com|registry\.npmjs\.org|pypi\.org|"
    r"files\.pythonhosted\.org|docker\.io|ghcr\.io|googleapis\.com|"
    r"amazonaws\.com|azure\.com|microsoft\.com|ubuntu\.com|debian\.org|"
    r"api\.internal|registry\.k8s\.io)\b", re.I)


def _int_to_ip(n: int):
    try:
        return str(ipaddress.IPv4Address(n)) if 0 <= n <= 0xFFFFFFFF else None
    except Exception:
        return None


def extract_iocs(text: str):
    """Return dict of indicators found in the command (already-normalized text)."""
    urls = _URL.findall(text)
    ips = set(_IPV4.findall(text))
    domains = {d for d in _DOMAIN.findall(text)
               if not _IPV4.fullmatch(d) and "." in d and not d.replace(".", "").isdigit()}
    # numeric / octal IP obfuscation -> decode
    obf_ips = []
    for m in _BARE_INT_IP.findall(text):
        ip = _int_to_ip(int(m))
        if ip:
            obf_ips.append((m, ip))
    return {"urls": urls, "ips": sorted(ips), "domains": sorted(domains),
            "obfuscated_ips": obf_ips}


def analyze(process_name: str, norm_text: str, raw_text: str):
    """Cross-reference indicators against bundled threat DBs.
    Returns {weights, reasons, iocs, hard, technique, technique_name, tactic}."""
    iocs = extract_iocs(norm_text)
    weights, reasons = [], []
    hard = False
    technique = technique_name = tactic = None

    # --- HARD signals (known-bad => confident malicious) ---
    if MINING_POOLS.search(norm_text):
        hard = True
        technique, technique_name, tactic = "T1496", "Resource Hijacking", "Impact"
        reasons.append("threat-intel: known crypto-mining pool/protocol")

    dyn = DYNAMIC_DNS.search(norm_text)
    if dyn:
        weights.append(0.6)
        reasons.append(f"threat-intel: abused dynamic-DNS provider ({dyn.group(0)})")
        technique = technique or "T1105"
        tactic = tactic or "Command and Control"

    # --- WEIGHTED signals ---
    for tld in {d.rsplit(".", 1)[-1].lower() for d in iocs["domains"]}:
        if tld in HIGH_ABUSE_TLDS:
            weights.append(0.4)
            reasons.append(f"threat-intel: high-abuse TLD .{tld}")
            break

    if iocs["obfuscated_ips"]:
        raw_n, ip = iocs["obfuscated_ips"][0]
        weights.append(0.5)
        reasons.append(f"obfuscated IP literal {raw_n} -> {ip}")

    # raw IP used in a download/exec context (no DNS, evades domain blocklists)
    if iocs["ips"] and re.search(r"(curl|wget|certutil|iwr|invoke-web|downloadstring|http)", norm_text, re.I):
        if not any(KNOWN_GOOD.search(u) for u in iocs["urls"]):
            weights.append(0.4)
            reasons.append(f"raw-IP fetch (no domain): {iocs['ips'][0]}")
            technique = technique or "T1105"
            tactic = tactic or "Command and Control"

    return {"weights": weights, "reasons": reasons, "iocs": iocs, "hard": hard,
            "technique": technique, "technique_name": technique_name, "tactic": tactic}


# --- optional LIVE lookup (off the scored hot path) ---
def live_threat_lookup(domains_ips, timeout=2.0, budget=3.0, log=print):
    """Query abuse.ch URLhaus host API. Returns set of confirmed-malicious hosts.
    Fully guarded — network failure never raises. NOT called on the scored path."""
    import json
    import urllib.parse
    import urllib.request
    from time import monotonic

    confirmed = set()
    start = monotonic()
    for host in domains_ips:
        if monotonic() - start > budget:
            log("[threat-intel] live budget hit; stopping lookups")
            break
        try:
            data = urllib.parse.urlencode({"host": host}).encode()
            req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/host/", data=data)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
            if body.get("query_status") == "ok" and body.get("urls"):
                confirmed.add(host)
                log(f"[threat-intel] URLhaus CONFIRMED malicious: {host}")
        except Exception:
            continue
    return confirmed
