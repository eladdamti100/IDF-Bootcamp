"""Evasion logic — the "smart red team" core.

Two jobs:
  1. ``blend`` — interleave the 20 malicious rows throughout the ~200 benign
     rows using stratified placement, so they are spread across the timeline
     rather than clustered (positional blending).
  2. ``obfuscate`` — optional, conservative transforms applied to a subset of
     malicious command lines to lower their signal against naive regex /
     keyword detectors while keeping them genuinely malicious and explainable.

Note: whatever malicious command we emit *becomes* the shared ground truth, so
obfuscating a command does not hide it from scoring — it only makes detection
harder, which is exactly the pressure we want for testing the Blue detector.
"""

from __future__ import annotations

import base64
import random


def blend(malicious: list[dict], benign: list[dict], seed: int) -> list[dict]:
    """Interleave malicious rows evenly across the benign timeline.

    Splits the combined timeline into ``len(malicious)`` strata and drops one
    malicious row into a random position within each stratum, so no two
    malicious commands are adjacent and they span beginning -> end.
    """
    rng = random.Random(seed ^ 0xB1E4D)
    m = len(malicious)
    total = m + len(benign)
    if m == 0:
        return list(benign)

    stride = total / m
    slots: list[int] = []
    used: set[int] = set()
    for i in range(m):
        lo = int(i * stride)
        hi = int((i + 1) * stride) - 1
        hi = max(hi, lo)
        pos = rng.randint(lo, hi)
        while pos in used:
            pos = (pos + 1) % total
        used.add(pos)
        slots.append(pos)

    benign_iter = iter(benign)
    out: list[dict] = []
    mal_by_slot = dict(zip(sorted(slots), malicious))
    for pos in range(total):
        if pos in mal_by_slot:
            out.append(mal_by_slot[pos])
        else:
            out.append(next(benign_iter))
    return out


# --------------------------------------------------------------------------- #
# Conservative obfuscation transforms. Each returns a new command_line string
# that is semantically equivalent (still malicious) but lower-signal. We only
# apply a transform when it keeps the command realistic and explainable.
# --------------------------------------------------------------------------- #

def _b64_wrap_linux(cmd: str) -> str:
    enc = base64.b64encode(cmd.encode()).decode()
    return f"echo {enc} | base64 -d | bash"


def _env_indirection_linux(cmd: str) -> str:
    # Hide a sensitive token (e.g. a path) behind an env var.
    return f"X=$(printf %s '{cmd}'); eval \"$X\""


def _powershell_b64(cmd: str) -> str:
    enc = base64.b64encode(cmd.encode("utf-16-le")).decode()
    return f"powershell -nop -w hidden -enc {enc}"


def obfuscate(malicious: list[dict], os_name: str, level: int, seed: int) -> list[dict]:
    """Apply moderate obfuscation to a fraction of malicious rows.

    level 0 = none, 1 = light (~25%), 2 = aggressive (~50%). The most
    signature-heavy commands are preferentially transformed. Rationale text is
    updated so the attack story still explains what each command does.
    """
    if level <= 0:
        return malicious
    rng = random.Random(seed ^ 0x0BF5)
    frac = 0.25 if level == 1 else 0.5

    # Prefer transforming the loudest commands (those with classic keywords).
    loud = ("shadow", "/dev/tcp", "-enc", "vssadmin", "mimikatz", "passwd",
            "crontab", "MiniDump", "Set-MpPreference", "reverse", "bash -i")

    def loudness(row: dict) -> int:
        c = row["command_line"].lower()
        return sum(1 for k in loud if k.lower() in c)

    order = sorted(range(len(malicious)), key=lambda i: -loudness(malicious[i]))
    n_transform = max(1, int(len(malicious) * frac))
    targets = set(order[:n_transform])

    out: list[dict] = []
    for i, row in enumerate(malicious):
        if i not in targets:
            out.append(row)
            continue
        new = dict(row)
        cmd = row["command_line"]
        if os_name == "linux":
            transform = rng.choice([_b64_wrap_linux, _env_indirection_linux])
            new["process_name"] = "bash"
        else:
            transform = _powershell_b64
            new["process_name"] = "powershell.exe"
        new["command_line"] = transform(cmd)
        new["rationale"] = f"{row['rationale']} (Obfuscated; decodes to: {cmd})"
        out.append(new)
    return out
