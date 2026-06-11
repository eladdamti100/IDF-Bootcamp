"""Layer 0 — de-obfuscation normalizer (the highest-ROI step most teams skip).

A FIXPOINT LOOP, not a single pass: combined obfuscation (e.g. caret + base64)
requires stripping the syntactic layer BEFORE the base64 blob is even visible.
The `was_obfuscated` delta (raw != normalized) is itself a high-precision signal.
"""
import re
import base64
import binascii

# in-word quote insertion:  po""wershell  ->  powershell   ;   re"g" "s"a"v"e -> reg save
_INWORD_QUOTE = re.compile(r'(?<=\w)["\']+(?=\w)')
_MULTISPACE = re.compile(r"\s{2,}")
# decode threshold is low (12) because garbage decodes are rejected by the
# printable-ratio check in safe_b64_decode; real -enc payloads are far longer.
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
# env-var styles we can resolve trivially
_WIN_VAR = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")

# very common Windows env vars worth resolving so signatures match
_KNOWN_WIN_VARS = {
    "comspec": "cmd.exe",
    "systemroot": "c:\\windows",
    "windir": "c:\\windows",
}


def _resolve_set_vars(cmd: str) -> str:
    """Resolve `set a=power & set b=shell & %a%%b%` style splitting."""
    assigns = dict(re.findall(r"set\s+([A-Za-z_]\w*)=([^\s&|]+)", cmd, flags=re.I))
    if not assigns:
        return cmd

    def repl(m):
        name = m.group(1).lower()
        for k, v in assigns.items():
            if k.lower() == name:
                return v
        return _KNOWN_WIN_VARS.get(name, m.group(0))

    return _WIN_VAR.sub(repl, cmd)


def _strip_path_traversal(cmd: str) -> str:
    return re.sub(r"\\[^\\/]+\\\.\.\\", "\\\\", cmd)


def _decode_bytes(raw: bytes) -> str:
    """Pick the right text encoding. PowerShell -enc is UTF-16LE (many null
    bytes for ASCII text); plain base64 is usually UTF-8. Returns "" if neither
    yields clean text."""
    if not raw:
        return ""
    null_ratio = raw.count(0) / len(raw)
    order = ("utf-16-le", "utf-8", "latin-1") if null_ratio > 0.20 else ("utf-8", "utf-16-le", "latin-1")
    for enc in order:
        try:
            txt = raw.decode(enc)
        except (UnicodeDecodeError, ValueError):
            continue
        if not txt:
            continue
        printable = sum(c.isprintable() or c.isspace() for c in txt)
        if printable / len(txt) > 0.85:
            return txt.replace("\x00", "")
    return ""


def safe_b64_decode(blob: str) -> str:
    """Decode a base64 blob defensively. Returns "" on any failure — never raises."""
    for variant in (blob, blob + "=" * (-len(blob) % 4)):
        try:
            raw = base64.b64decode(variant, validate=False)
        except (binascii.Error, ValueError):
            continue
        txt = _decode_bytes(raw)
        if txt:
            return txt
    return ""


def find_b64_blobs(cmd: str):
    return _B64_BLOB.findall(cmd)


def normalize(command_line: str, is_windows: bool = True, max_iter: int = 5):
    """Return (normalized_text, was_obfuscated, decoded_payloads).

    Iterates to a fixpoint so layered obfuscation collapses. `decoded_payloads`
    holds any base64 we recovered, appended to the normalized text so downstream
    signature/entropy stages scan it too.
    """
    raw = command_line
    cmd = command_line
    decoded = []
    prev = None
    # NOTE: case is PRESERVED through the loop — base64 is case-sensitive, so we
    # must decode before any lowercasing. Lowercasing happens once at the end.
    for _ in range(max_iter):
        if cmd == prev:
            break
        prev = cmd
        cmd = cmd.replace("^", "")                 # 1. carets
        cmd = _INWORD_QUOTE.sub("", cmd)           # 2. in-word quotes
        cmd = _MULTISPACE.sub(" ", cmd)            # 3. whitespace padding
        cmd = _resolve_set_vars(cmd)               # 4. set a=..&%a%%b%
        cmd = _strip_path_traversal(cmd)           # 5. \..\ traversal
        # 6. flags now visible -> decode base64 blobs (case intact) and re-scan
        for blob in find_b64_blobs(cmd):
            txt = safe_b64_decode(blob)
            if txt and txt not in decoded:
                decoded.append(txt)
                cmd = cmd + " ||DECODED|| " + txt

    if is_windows:
        cmd = cmd.lower()
    normalized = cmd.strip()
    # compare on a whitespace/case-insensitive basis so trivial diffs don't false-fire
    was_obfuscated = _MULTISPACE.sub(" ", raw.strip().lower()) != _MULTISPACE.sub(" ", normalized)
    return normalized, was_obfuscated, decoded
