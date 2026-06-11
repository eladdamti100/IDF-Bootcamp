"""Layer 2 — heuristic scoring (the suspicion score / "ציון").

Combines weak structural signals via noisy-OR (stays in [0,1], principled,
interpretable). Every contributing signal records a human-readable reason for
the pitch ("why was this flagged"). Strong signatures dominate; weak signals
push borderline rows into the gray zone for the verifier rather than flagging.
"""
import math
import re
from . import signatures as sig

_OBF_CHARS = re.compile(r"[\^\"'`%$!]")
_SPECIAL = re.compile(r"[^\w\s]")
_SPACE_RUN = re.compile(r" {2,}")
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
# any char well outside ASCII -> likely homoglyph / unicode-insertion obfuscation
_HIGH_UNICODE = re.compile(r"[ -￿]")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _noisy_or(weights):
    p = 1.0
    for w in weights:
        p *= (1.0 - w)
    return 1.0 - p


def score_row(process_name: str, raw_cmd: str, norm_text: str, was_obfuscated: bool):
    """Return (score in [0,1], verdict_hint, reasons[list], technique, tactic).

    verdict_hint is one of: 'malicious' (signature), 'benign' (allowlist), None (heuristic).
    """
    reasons = []
    technique = tactic = None

    # --- confident benign: whole-command allowlist + clean ---
    args = raw_cmd
    ent = shannon_entropy(norm_text)
    if sig.is_allowlisted(norm_text) and not was_obfuscated and ent < 4.6:
        return 0.02, "benign", ["allowlisted benign template"], None, None

    # --- confident malicious: signature hit (take the strongest) ---
    hits = sig.match_signatures(norm_text)
    if hits:
        hits.sort(key=lambda h: h[3], reverse=True)
        tid, tname, tac, sc = hits[0]
        technique, tactic = tid, tac
        reasons.append(f"signature: {tname} ({tid})")
        # obfuscation on top of a signature only raises confidence
        if was_obfuscated:
            sc = min(0.99, sc + 0.02)
            reasons.append("also obfuscated (raw != normalized)")
        return sc, "malicious", reasons, technique, tactic

    # --- heuristic gray-zone scoring via weak signals (noisy-OR) ---
    weights = []
    length = max(1, len(raw_cmd))

    if was_obfuscated:
        weights.append(0.55)
        reasons.append("obfuscation detected (raw != normalized)")

    obf_density = len(_OBF_CHARS.findall(raw_cmd)) / length
    if obf_density > 0.04:
        weights.append(min(0.5, obf_density * 6))
        reasons.append(f"high obfuscation-char density ({obf_density:.0%})")

    runs = _SPACE_RUN.findall(raw_cmd)
    max_run = max((len(r) for r in runs), default=0)
    if max_run >= 15:
        weights.append(0.5)
        reasons.append(f"whitespace padding ({max_run} spaces)")

    if ent > 4.8:
        weights.append(min(0.55, (ent - 4.8) * 0.4 + 0.3))
        reasons.append(f"high entropy {ent:.1f} (encoded/encrypted)")

    if _B64.search(norm_text):
        weights.append(0.35)
        reasons.append("base64-shaped blob")

    if _HIGH_UNICODE.search(raw_cmd):
        weights.append(0.45)
        reasons.append("non-ASCII chars (homoglyph/unicode obfuscation)")

    # process_name vs command_line mismatch (masquerading)
    pname = (process_name or "").lower().replace(".exe", "").strip()
    if pname and pname not in norm_text and pname not in ("cmd", "sh", "bash", "powershell"):
        # the named binary never appears in its own command line -> suspicious
        if any(tok in norm_text for tok in ("http", "downloadstring", "-enc", "/dev/tcp", "minidump")):
            weights.append(0.5)
            reasons.append(f"process/argument mismatch (name '{pname}')")

    if sig.has_lolbin(norm_text):
        weights.append(0.18)  # WEAK only
        reasons.append("LOLBin present (weak signal)")

    score = _noisy_or(weights)
    return score, None, reasons, technique, tactic
