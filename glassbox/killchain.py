"""Layer 4 — kill-chain reconstruction + scenario naming (the +20 lever).

Deterministic: works even when the LLM is skipped by the kill-switch.
Two jobs:
  (a) cross-row boost  — detection signal: a borderline row that completes a
      coherent multi-tactic chain is boosted; an isolated scary row is not.
      Discovery rows get a density boost (10 recon cmds in a row != 1).
  (b) story            — order flagged techniques along the kill chain, name
      the scenario, emit a short professional narrative.
"""
from collections import Counter
from . import signatures as sig

TACTIC_RANK = {t: i for i, t in enumerate(sig.TACTIC_ORDER)}


def cross_row_boost(rows):
    """Mutate row scores in place using cross-row context. `rows` is a list of
    dicts with keys: score, verdict_hint, tactic, norm, reasons."""
    # distinct tactics among confident-malicious signature hits
    confident_tactics = {r["tactic"] for r in rows
                         if r["verdict_hint"] == "malicious" and r["tactic"]}
    chain_active = len(confident_tactics) >= 3  # a real campaign spans tactics

    # discovery density
    disc_idx = [i for i, r in enumerate(rows) if sig.is_discovery(r["norm"])]
    disc_dense = len(disc_idx) >= 5

    for i, r in enumerate(rows):
        if r["verdict_hint"] in ("malicious", "benign"):
            continue  # only nudge gray-zone rows; never override confident calls
        boosted = r["score"]
        if disc_dense and i in disc_idx:
            if chain_active:
                # confirmed multi-tactic campaign + clustered recon => the recon
                # IS part of the attack (combination is malicious).
                boosted = max(boosted, 0.9)
                r["reasons"].append(
                    f"clustered recon during active kill-chain ({len(disc_idx)} discovery cmds)")
            else:
                boosted = 1.0 - (1.0 - boosted) * (1.0 - 0.30)
                r["reasons"].append(f"recon density ({len(disc_idx)} discovery cmds in dataset)")
        if chain_active and r["tactic"] and r["tactic"] in TACTIC_RANK:
            boosted = 1.0 - (1.0 - boosted) * (1.0 - 0.20)
            r["reasons"].append("extends active kill-chain")
        r["score"] = boosted


# scenario signatures: (name, predicate over the set of tactics+techniques present)
def classify_scenario(flagged):
    tactics = {r["tactic"] for r in flagged if r["tactic"]}
    tac_counts = Counter(r["tactic"] for r in flagged if r["tactic"])
    techs = " ".join((r["technique"] or "") for r in flagged) + " " + \
            " ".join(r["norm"] for r in flagged)

    # 1) hard, unambiguous Impact signatures win outright
    if "T1496" in techs or "xmrig" in techs or "donate-level" in techs or "stratum" in techs:
        return "Crypto Miner"
    if any(t in techs for t in ("T1490", "T1486", "T1485")) or \
       "vssadmin delete shadows" in techs or "bcdedit" in techs or ".enc" in techs or ".locked" in techs:
        return "Ransomware"

    # 2) tactic combinations that name a specific scenario
    if "Credential Access" in tactics and "Lateral Movement" in tactics:
        return "Lateral Movement / Credential Theft"
    if ("Collection" in tactics or "T1560" in techs) and \
       ("Exfiltration" in tactics or "T1041" in techs or "T1567" in techs):
        return "Data Exfiltration"

    # 3) otherwise name by the most scenario-DEFINING tactic present. Ubiquitous
    #    support tactics (Credential Access, Defense Evasion, Execution, Discovery)
    #    appear in almost every kill-chain, so they only decide when nothing more
    #    specific is present. Order = "climax" strength.
    PRIORITY = [
        ("Exfiltration", "Data Exfiltration"),
        ("Collection", "Data Exfiltration"),
        ("Lateral Movement", "Lateral Movement"),
        ("Persistence", "Persistence / Backdoor"),
        ("Command and Control", "Backdoor / C2"),
        ("Privilege Escalation", "Privilege Escalation"),
        ("Credential Access", "Credential Access"),
    ]
    for tac, name in PRIORITY:
        if tac in tactics:
            return name
    if tac_counts:
        top = tac_counts.most_common(1)[0][0]
        return {"Execution": "Backdoor / Remote Execution",
                "Discovery": "Reconnaissance / Discovery",
                "Defense Evasion": "Defense Evasion"}.get(top, top)
    return "Inconclusive"


_NARR = {
    "Execution": "executed attacker code",
    "Persistence": "established persistence",
    "Privilege Escalation": "escalated privileges",
    "Defense Evasion": "disabled defenses / cleared logs",
    "Credential Access": "harvested credentials",
    "Discovery": "performed host & account discovery",
    "Lateral Movement": "moved laterally to other hosts",
    "Collection": "staged & archived data",
    "Command and Control": "pulled tooling from a remote source",
    "Exfiltration": "exfiltrated data",
    "Impact": "delivered impact (destruction/ransom/mining)",
}


def build_story(flagged):
    """Return dict: {scenario, tactic_timeline, narrative}. Runs on ~20 rows."""
    if not flagged:
        return {"scenario": "No malicious activity detected",
                "tactic_timeline": [], "narrative": "No commands met the malicious threshold."}

    scenario = classify_scenario(flagged)

    # order tactics along the kill chain
    present = [r["tactic"] for r in flagged if r["tactic"]]
    ordered = sorted(set(present), key=lambda t: TACTIC_RANK.get(t, 99))

    # timeline: tactic -> example technique names
    bytac = {}
    for r in flagged:
        if r["tactic"]:
            bytac.setdefault(r["tactic"], [])
            tname = r.get("technique_name") or r["technique"]
            if tname and tname not in bytac[r["tactic"]]:
                bytac[r["tactic"]].append(tname)

    timeline = [{"tactic": t, "techniques": bytac.get(t, [])} for t in ordered]

    phrases = [_NARR.get(t, t.lower()) for t in ordered]
    if len(phrases) > 1:
        body = ", then ".join(phrases[:-1]) + ", and finally " + phrases[-1]
    else:
        body = phrases[0] if phrases else "performed suspicious actions"
    narrative = (f"The attacker {body}. "
                 f"Scenario: {scenario}.")
    return {"scenario": scenario, "tactic_timeline": timeline, "narrative": narrative}
