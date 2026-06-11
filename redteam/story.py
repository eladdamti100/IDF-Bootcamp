"""Render the written attack story (markdown) from a generated Result.

The story groups the 20 malicious commands by kill-chain phase and narrates a
beginning -> middle -> end, then lists every malicious command with its
rationale and how it was hidden.
"""

from __future__ import annotations

from . import scenarios

_NARRATIVE = {
    "initial-access": "The operator gains a foothold on the host.",
    "execution": "They run their first payload.",
    "persistence": "They wire up persistence so the access survives reboots.",
    "privilege-escalation": "They abuse a misconfiguration to gain higher privileges.",
    "defense-evasion": "They blind defenses and clean up traces.",
    "credential-access": "They harvest credentials for reuse.",
    "discovery": "They map the environment to plan their next move.",
    "lateral-movement": "They pivot to additional hosts.",
    "collection": "They gather the data they came for.",
    "command-and-control": "They keep a channel open to their infrastructure.",
    "exfiltration": "They smuggle the data out.",
    "impact": "They deliver the final objective.",
}


def build(result) -> str:
    desc = scenarios.describe(result.scenario_key)
    lines: list[str] = []
    lines.append(f"# Attack Story — {result.scenario}")
    lines.append("")
    lines.append(f"- **Scenario (matched):** `{result.scenario_key}` — {desc}")
    lines.append(f"- **Target OS:** {result.os_name}")
    lines.append(f"- **Dataset:** {result.total} commands "
                 f"({len(result.malicious)} malicious, {result.total - len(result.malicious)} benign)")
    lines.append(f"- **Generation source:** malicious={result.sources.get('malicious')}, "
                 f"benign={result.sources.get('benign')}")
    lines.append("")

    # Order malicious rows by canonical phase for the narrative.
    order = {p: i for i, p in enumerate(scenarios.PHASE_ORDER)}
    ordered = sorted(result.malicious,
                     key=lambda r: order.get(r.get("phase", ""), len(order)))

    lines.append("## The Story")
    lines.append("")
    seen_phase = set()
    step = 1
    for r in ordered:
        phase = r.get("phase", "") or "execution"
        if phase not in seen_phase:
            seen_phase.add(phase)
            lead = _NARRATIVE.get(phase, "")
            lines.append(f"**{step}. {phase}** — {lead}")
            step += 1
        rationale = r.get("rationale", "")
        lines.append(f"   - `{r['command_line']}`"
                     + (f"  \n     ↳ {rationale}" if rationale else ""))
    lines.append("")

    lines.append("## How It Was Hidden")
    lines.append("")
    lines.append("- Malicious commands reuse the same users, paths and tooling as the "
                 "benign noise so they don't stand out statistically.")
    lines.append("- Living-off-the-land binaries (curl, certutil, bitsadmin, rundll32, "
                 "powershell, openssl, ssh) are preferred over obvious malware names.")
    lines.append("- Several steps are individually low-signal — only their **sequence** "
                 "reveals the attack.")
    lines.append("- The 20 malicious commands are interleaved evenly across the timeline, "
                 "never clustered together.")
    lines.append("")

    lines.append("## Ground-Truth Malicious Commands")
    lines.append("")
    lines.append("| # | process | command_line | phase |")
    lines.append("|---|---------|--------------|-------|")
    for i, r in enumerate(ordered, 1):
        cmd = r["command_line"].replace("|", "\\|")
        lines.append(f"| {i} | `{r['process_name']}` | `{cmd}` | {r.get('phase', '')} |")
    lines.append("")
    return "\n".join(lines)
