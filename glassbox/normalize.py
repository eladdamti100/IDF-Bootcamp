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
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.\-]{1,8}://\S+", re.I)


def strip_urls(text: str) -> str:
    """Remove URL tokens so their paths (which contain '/' — a base64 char) are
    not mistaken for base64 blobs. Real -enc/decode payloads are never URLs."""
    return _URL_RE.sub(" ", text)


def looks_base64(s: str) -> bool:
    """Reject URL-path / identifier runs that merely use the base64 charset.
    Real base64 mixes character classes (and usually has uppercase) or '=' padding."""
    s = s.rstrip("=")
    if len(s) < 16:
        return False
    has_u = any(c.isupper() for c in s)
    has_l = any(c.islower() for c in s)
    has_d = any(c.isdigit() for c in s)
    # lowercase-only runs (URL paths like /repos/platform/commits) -> False
    return (has_u + has_l + has_d) >= 2 and has_u
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


def _ascii_printable_ratio(txt: str) -> float:
    if not txt:
        return 0.0
    ok = sum(1 for c in txt if 0x20 <= ord(c) <= 0x7E or c in "\t\n\r")
    return ok / len(txt)


def _decode_bytes(raw: bytes) -> str:
    """Pick the right text encoding. PowerShell -enc is UTF-16LE (many null
    bytes for ASCII text); plain base64 is UTF-8. Requires the result to be
    mostly *ASCII* printable — latin-1 maps every byte to a 'printable' char, so
    we must NOT accept it, or random bytes (e.g. a mis-detected URL path) sneak
    through. Returns "" if nothing yields clean ASCII text."""
    if not raw:
        return ""
    null_ratio = raw.count(0) / len(raw)
    order = ("utf-16-le", "utf-8") if null_ratio > 0.20 else ("utf-8", "utf-16-le")
    for enc in order:
        try:
            txt = raw.decode(enc)
        except (UnicodeDecodeError, ValueError):
            continue
        txt = txt.replace("\x00", "")
        if txt and _ascii_printable_ratio(txt) > 0.90:
            return txt
    return ""


def safe_b64_decode(blob: str) -> str:
    """Decode a base64 blob defensively. Returns "" on any failure — never raises."""
    if not looks_base64(blob):
        return ""
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
    # scan URL-stripped text so URL paths (which contain '/') aren't mistaken
    # for base64, and keep only blobs that actually look like base64.
    return [b for b in _B64_BLOB.findall(strip_urls(cmd)) if looks_base64(b)]


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
