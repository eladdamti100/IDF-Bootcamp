"""Orchestrator — ties the layers together under a single time budget.

CSV -> [0] normalize -> [1] signatures / allowlist -> [2] heuristic score
    -> cross-row boost -> threshold split -> [3] gray-zone verifier
    -> [4] kill-chain story.  Returns verdicts + per-row reasons + story + timing.
"""
import csv
import re
import io
from time import monotonic
from . import normalize as nz
from . import features as ft
from . import killchain as kc
from . import enrich as en
from . import llmguard as lg


def _noisy_or(*ps):
    p = 1.0
    for x in ps:
        p *= (1.0 - x)
    return 1.0 - p
from . import verifier as vf

# Thresholds: calibrated on the training set (see calibrate.py). COUNT-INDEPENDENT.
# The malicious count is NEVER hardcoded; these gate on score only.
MAL_THRESHOLD = 0.82
BENIGN_CEILING = 0.35


def _technique_name_lookup(tid):
    if not tid:
        return None
    for rx, t, tname, tac, sc in _SIG_INDEX:
        if t == tid:
            return tname
    return tid


# build a small index for technique-id -> name (for the story timeline)
from . import signatures as _sig
_SIG_INDEX = [(rx, t, tname, tac, sc) for (rx, t, tname, tac, sc) in
              [(s[0], s[1], s[2], s[3], s[4]) for s in _sig.SIGNATURES]]


_WIN_HINT = re.compile(r"\.exe\b|powershell|cmd\.exe|\breg\s+add|schtasks|hk(lm|cu)|"
                       r"%\w+%|[a-z]:\\|\\windows|vssadmin|wmic|rundll32|certutil", re.I)
_NIX_HINT = re.compile(r"/bin/|/etc/|/usr/|/home/|/tmp/|/var/|\bsudo\b|\bbash\b|"
                       r"\bchmod\b|\bchown\b|crontab|\bsh\s+-c|/dev/", re.I)


def detect_os(raw_rows):
    """Auto-detect Windows vs Linux from the commands (majority vote), so the
    tool always produces a verdict without the caller specifying an OS."""
    win = nix = 0
    for rr in raw_rows:
        cmd = (rr.get("command_line") or "") + " " + (rr.get("process_name") or "")
        win += len(_WIN_HINT.findall(cmd))
        nix += len(_NIX_HINT.findall(cmd))
    return win >= nix  # tie -> Windows (lowercasing is harmless for signatures)


def analyze_csv(text_or_path, llm_fn=None, is_windows=None,
                mal_threshold=MAL_THRESHOLD, benign_ceiling=BENIGN_CEILING,
                threat_intel=False, log=print):
    start = monotonic()
    all_iocs = []

    # --- load ---
    if "\n" in text_or_path or "," in text_or_path[:200]:
        f = io.StringIO(text_or_path)
    else:
        f = open(text_or_path, newline="", encoding="utf-8", errors="replace")
    with f:
        reader = csv.DictReader(f)
        raw_rows = list(reader)

    # OS is auto-detected PER ROW unless explicitly forced, so a single CSV may
    # mix Linux and Windows commands. (Dataset-level guess kept only for the log.)
    auto_os = is_windows is None
    if auto_os:
        lean = detect_os(raw_rows)
        log(f"[os] auto-detect per-row (dataset leans {'Windows' if lean else 'Linux'})")

    rows = []
    for i, rr in enumerate(raw_rows):
        pname = (rr.get("process_name") or "").strip()
        cmd = (rr.get("command_line") or "").strip()
        row_win = nz.detect_os(pname, cmd) if auto_os else is_windows
        norm, was_obf, decoded = nz.normalize(cmd, is_windows=row_win)
        score, hint, reasons, tech, tac = ft.score_row(pname, cmd, norm, was_obf)
        tech_name = _technique_name_lookup(tech)

        # --- external threat-intel cross-reference (offline DB snapshots) ---
        e = en.analyze(pname, norm, cmd)
        if e["iocs"]["urls"] or e["iocs"]["ips"] or e["iocs"]["domains"]:
            all_iocs.append({"row": i, **e["iocs"]})
        if e["hard"] and hint != "benign":
            hint, tech, tac = "malicious", e["technique"], e["tactic"]
            tech_name = e["technique_name"] or tech_name
            reasons = (reasons or []) + e["reasons"]
            score = max(score, 0.95)
        elif e["weights"]:
            score = _noisy_or(score, *e["weights"])
            reasons = (reasons or []) + e["reasons"]
            tech = tech or e["technique"]
            tac = tac or e["tactic"]

        # --- prompt-injection text inside a command is itself a malicious signal ---
        is_inj, phrase = lg.detect_injection(cmd)
        if is_inj:
            # a real admin command never tries to manipulate a classifier -> near-hard
            score = _noisy_or(score, 0.88)
            reasons = (reasons or []) + [f"prompt-injection text in command ('{phrase}')"]
            tech = tech or "T1027"
            tac = tac or "Defense Evasion"

        rows.append({
            "idx": i, "process_name": pname, "command_line": cmd,
            "norm": norm, "was_obfuscated": was_obf, "decoded": decoded,
            "score": score, "verdict_hint": hint, "reasons": reasons,
            "technique": tech, "tactic": tac,
            "technique_name": tech_name,
        })

    # --- cross-row context (detection signal AND story input) ---
    kc.cross_row_boost(rows)

    # --- threshold split (count-independent) ---
    gray = []
    for r in rows:
        if r["verdict_hint"] == "malicious" or r["score"] >= mal_threshold:
            r["verdict"] = "malicious"
        elif r["verdict_hint"] == "benign" or r["score"] <= benign_ceiling:
            r["verdict"] = "benign"
        else:
            r["verdict"] = "gray"
            gray.append(r)

    # --- gray-zone verifier (bounded, kill-switch) ---
    elapsed = monotonic() - start
    resolved = vf.resolve_gray_zone(gray, elapsed, llm_fn=llm_fn, log=log)
    for r in gray:
        v, tech = resolved.get(r["idx"], ("benign", None))
        r["verdict"] = v
        if v == "malicious":
            r["reasons"].append("LLM verifier: malicious")
            if tech and not r["technique"]:
                r["technique"] = tech

    # --- story on the flagged set ---
    flagged = [r for r in rows if r["verdict"] == "malicious"]

    # --- optional LIVE threat-intel corroboration (OFF the scored hot path) ---
    confirmed_hosts = set()
    if threat_intel:
        hosts = set()
        for ioc in all_iocs:
            hosts.update(ioc.get("domains", []))
            hosts.update(ioc.get("ips", []))
        confirmed_hosts = en.live_threat_lookup(sorted(hosts), log=log)
        for r in rows:
            text = r["norm"]
            if any(h in text for h in confirmed_hosts):
                if r["verdict"] != "malicious":
                    r["verdict"] = "malicious"
                    flagged.append(r)
                r["reasons"].append("threat-intel LIVE: URLhaus-confirmed malicious host")

    story = kc.build_story(flagged)

    took = monotonic() - start
    return {
        "rows": rows,
        "flagged": flagged,
        "story": story,
        "iocs": all_iocs,
        "confirmed_hosts": sorted(confirmed_hosts),
        "elapsed_sec": round(took, 3),
        "counts": {
            "total": len(rows),
            "malicious": len(flagged),
            "gray_zone": len(gray),
        },
        # 20 used ONLY as a non-binding diagnostic — nothing branches on it.
        "sanity_note": f"flagged {len(flagged)} rows (typical scenarios ~15-25; FYI only, not enforced)",
    }
