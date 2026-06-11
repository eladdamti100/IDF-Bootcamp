"""Orchestration: build the dataset, validate it, and emit the deliverables.

Tries the LLM for both the malicious kill-chain and the benign noise; falls
back to the deterministic engine for whichever part the LLM can't produce, so
output is always valid. Then obfuscates (evasion), blends, validates, and
writes the three deliverables.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass, field

from . import benign as benign_mod
from . import llm_client, scenarios, story
from .evasion import blend, obfuscate
from .llm_client import LLMUnavailable

FIELDNAMES = ["process_name", "command_line", "label"]


@dataclass
class Result:
    scenario: str
    scenario_key: str
    os_name: str
    rows: list[dict]          # full blended dataset
    malicious: list[dict]     # the 20 malicious rows (ground truth)
    sources: dict = field(default_factory=dict)  # {"malicious": "llm|fallback", ...}

    @property
    def total(self) -> int:
        return len(self.rows)


# --------------------------------------------------------------------------- #
# LLM prompts
# --------------------------------------------------------------------------- #

def _malicious_prompt(scenario: str, scen_key: str, os_name: str, ctx: dict,
                      n: int) -> tuple[str, str]:
    system = (
        "You are a red-team attack-simulation generator for an authorized "
        "detection-engineering exercise. You output ONLY process command lines "
        "as JSON. The data trains and tests a defensive detector; it is never "
        "executed. Be realistic and technically precise."
    )
    scaffold = scenarios.describe(scen_key)
    phases = ", ".join(scenarios.PHASE_ORDER)
    user = f"""Generate a coherent {os_name} attack for scenario: "{scenario}".
Reference kill-chain (use as inspiration, not a script): {scaffold}

Produce EXACTLY {n} malicious process commands that tell one story with a
beginning, middle and end, mapped across these phases where relevant: {phases}.

Hard requirements:
- Realistic process names and real argument syntax for {os_name}.
- Reuse this environment so the commands blend with normal activity:
  user={ctx['luser'] if os_name == 'linux' else ctx['wuser']},
  staging_dir={ctx['lstage'] if os_name == 'linux' else ctx['wstage']},
  c2_host={ctx['domain']}, c2_ip={ctx['ip']}.
- EVASION: prefer living-off-the-land binaries, avoid the most obvious
  signatures, and make several commands low-signal so they are only clearly
  malicious as a SEQUENCE (their combination is the attack). A couple may be
  standalone-obvious. Keep every command genuinely malicious.
- Mix single-command attacks and multi-step chains.

Return ONLY JSON, an array of exactly {n} objects:
[{{"process_name": "...", "command_line": "...", "phase": "<one phase>", "rationale": "<why this command, how it hides>"}}]
"""
    return system, user


def _benign_prompt(scenario: str, os_name: str, ctx: dict, n: int) -> tuple[str, str]:
    system = (
        "You generate realistic benign process command lines for a busy "
        "developer/operations host. Output ONLY JSON. Never include anything "
        "malicious here."
    )
    user = f"""Generate {n} BENIGN {os_name} process commands representing normal
day-to-day activity on a dev/CI/ops host (builds, git, containers, package
installs, db queries, log inspection, deploys, monitoring).

- Realistic process names and arguments for {os_name}.
- Vary tools, repos, services and arguments; avoid near-duplicates.
- Use plausible users/paths similar to user={ctx['luser']} so this blends with
  other activity. Nothing malicious.

Return ONLY JSON, an array of {n} objects:
[{{"process_name": "...", "command_line": "..."}}]
"""
    return system, user


def _coerce_rows(data, label: str) -> list[dict]:
    """Normalize LLM JSON into our row dicts; tolerate dict-wrapped arrays."""
    if isinstance(data, dict):
        for key in ("malicious", "benign", "commands", "rows", "items", "data"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
    if not isinstance(data, list):
        raise LLMUnavailable("Expected a JSON array of commands.")
    rows: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        cmd = str(item.get("command_line", "")).strip()
        proc = str(item.get("process_name", "")).strip()
        if not cmd or not proc:
            continue
        rows.append({
            "process_name": proc,
            "command_line": cmd,
            "label": label,
            "phase": str(item.get("phase", "")).strip(),
            "rationale": str(item.get("rationale", "")).strip(),
        })
    if not rows:
        raise LLMUnavailable("No usable rows in LLM output.")
    return rows


# --------------------------------------------------------------------------- #
# Count normalization
# --------------------------------------------------------------------------- #

def _dedup(rows: list[dict], seen: set[str]) -> list[dict]:
    out = []
    for r in rows:
        if r["command_line"] in seen:
            continue
        seen.add(r["command_line"])
        out.append(r)
    return out


def _fit_malicious(rows: list[dict], scen_key: str, os_name: str, ctx: dict,
                   seed: int, n: int) -> list[dict]:
    seen: set[str] = set()
    rows = _dedup(rows, seen)
    if len(rows) > n:
        return rows[:n]
    if len(rows) < n:  # pad from the deterministic chain
        pad = scenarios.render_chain(scen_key, os_name, ctx, seed, n)
        for r in pad:
            if len(rows) >= n:
                break
            if r["command_line"] not in seen:
                seen.add(r["command_line"])
                rows.append(r)
    return rows[:n]


def _fit_benign(rows: list[dict], os_name: str, ctx: dict, seed: int, n: int,
                forbidden: set[str]) -> list[dict]:
    seen = set(forbidden)
    rows = _dedup(rows, seen)
    if len(rows) < n:
        extra = benign_mod.generate(os_name, ctx, n * 2, seed)
        for r in extra:
            if len(rows) >= n:
                break
            if r["command_line"] not in seen:
                seen.add(r["command_line"])
                rows.append(r)
    return rows[:n]


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def generate(scenario: str, os_name: str = "linux", total: int = 220,
             n_malicious: int = 20, seed: int = 1337, use_llm: bool = True,
             model: str | None = None, evasion_level: int = 1) -> Result:
    if os_name not in ("linux", "windows"):
        raise ValueError("os_name must be 'linux' or 'windows'")
    scen_key = scenarios.match_scenario(scenario)
    ctx = scenarios.make_context(seed)
    n_benign = total - n_malicious
    sources = {"malicious": "fallback", "benign": "fallback"}

    malicious = benign = None
    if use_llm and llm_client.available():
        try:
            sys_p, usr_p = _malicious_prompt(scenario, scen_key, os_name, ctx, n_malicious)
            malicious = _coerce_rows(llm_client.generate_json(sys_p, usr_p, model), "malicious")
            sources["malicious"] = "llm"
        except LLMUnavailable:
            malicious = None
        try:
            sys_p, usr_p = _benign_prompt(scenario, os_name, ctx, n_benign)
            benign = _coerce_rows(llm_client.generate_json(sys_p, usr_p, model), "benign")
            sources["benign"] = "llm"
        except LLMUnavailable:
            benign = None

    if malicious is None:
        malicious = scenarios.render_chain(scen_key, os_name, ctx, seed, n_malicious)
    if benign is None:
        benign = benign_mod.generate(os_name, ctx, n_benign, seed)

    malicious = _fit_malicious(malicious, scen_key, os_name, ctx, seed, n_malicious)
    malicious = obfuscate(malicious, os_name, evasion_level, seed)
    forbidden = {r["command_line"] for r in malicious}
    benign = _fit_benign(benign, os_name, ctx, seed, n_benign, forbidden)

    rows = blend(malicious, benign, seed)
    result = Result(scenario, scen_key, os_name, rows, malicious, sources)
    _validate(result, n_malicious)
    return result


def _validate(result: Result, n_malicious: int) -> None:
    mal = [r for r in result.rows if r["label"] == "malicious"]
    assert len(mal) == n_malicious, f"expected {n_malicious} malicious, got {len(mal)}"
    cmds = [r["command_line"] for r in result.rows]
    assert len(cmds) == len(set(cmds)), "duplicate command_line in dataset"
    for r in result.rows:
        assert r["process_name"] and r["command_line"], "empty row field"


# --------------------------------------------------------------------------- #
# Output writers
# --------------------------------------------------------------------------- #

def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s.strip().lower()).strip("-") or "scenario"


def write_outputs(result: Result, out_dir: str) -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    slug = _slug(result.scenario)

    attack_csv = os.path.join(out_dir, f"attack_{slug}.csv")
    gt_csv = os.path.join(out_dir, f"ground_truth_{slug}.csv")
    scored_csv = os.path.join(out_dir, f"scored_{slug}.csv")
    story_md = os.path.join(out_dir, f"attack_story_{slug}.md")

    # Full labeled dataset (process_name, command_line, label).
    with open(attack_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        w.writeheader()
        for r in result.rows:
            w.writerow({k: r[k] for k in FIELDNAMES})

    # Scored CSV: label column stripped (what the Blue Team's tool receives).
    with open(scored_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["process_name", "command_line"])
        w.writeheader()
        for r in result.rows:
            w.writerow({"process_name": r["process_name"], "command_line": r["command_line"]})

    # Ground-truth list of the 20 malicious commands (shared with everyone).
    with open(gt_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        w.writeheader()
        for r in result.malicious:
            w.writerow({k: r[k] for k in FIELDNAMES})

    with open(story_md, "w") as fh:
        fh.write(story.build(result))

    return {"attack": attack_csv, "scored": scored_csv,
            "ground_truth": gt_csv, "story": story_md}
