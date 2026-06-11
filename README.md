# IDF-Bootcamp — Red Team Attacker Generator

> **Context:** We are the **Blue Team** in the Upwind "AI Red Team vs. Blue Team"
> bootcamp. This branch (`red-team-attacker`) contains an **internal adversary
> tool** we use to stress-test our own detection system with realistic, evasive
> attack data — standing in for a Red Team so our defense gets exercised against
> something harder than toy input. It is **not** part of the defensive product on
> `main`.

The tool is the Red Team deliverable from the brief: given a scenario, it
generates a CSV of ~220 process commands (**exactly 20 malicious** + ~200 benign),
a separate labeled **ground-truth** list of the 20 malicious commands, and a
written **attack story**.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # optional — only needed for the LLM path
```

The tool runs **fully offline** with `--no-llm`; the LLM is optional.

## API key (from 1Password)

Eldan shared the AI API key via a 1Password link in Slack. Open it, copy the key,
and export it. The client auto-detects the provider:

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # default (Claude)
# or
export OPENAI_API_KEY=sk-...             # if the key is an OpenAI key
```

If no key is set, the tool prints a notice and uses the offline engine.

## Usage

```bash
# LLM-driven (needs a key)
python -m redteam "ransomware" --os linux --out ./out
python -m redteam "lateral movement" --os windows --out ./out

# Offline / demo-safe (deterministic, no key or network)
python -m redteam "crypto miner" --no-llm --seed 7 --out ./out
```

### Options

| Flag | Default | Meaning |
|------|---------|---------|
| `scenario` | — | Scenario text, e.g. `ransomware`, `lateral movement`, `crypto miner`, `data exfiltration`, `persistence`, `privilege escalation`, `credential access`, `backdoor`. Unknown scenarios fall back to a generic kill-chain. |
| `--os` | `linux` | `linux` or `windows`. |
| `--out` | `./out` | Output directory. |
| `--total` | `220` | Total rows. |
| `--malicious` | `20` | Number of malicious commands. |
| `--seed` | `1337` | Reproducible generation. |
| `--evasion` | `1` | Obfuscation level: `0` none, `1` light, `2` aggressive. |
| `--model` | auto | Override the LLM model id. |
| `--no-llm` | off | Force the offline deterministic engine. |

## Outputs (in `--out`)

| File | Purpose |
|------|---------|
| `attack_<scenario>.csv` | Full labeled dataset (`process_name,command_line,label`). |
| `scored_<scenario>.csv` | Same rows with the **label stripped** — this is what you feed to the detector. |
| `ground_truth_<scenario>.csv` | The 20 malicious rows — submit to the judges. |
| `attack_story_<scenario>.md` | Narrative + per-command rationale + how each was hidden. |

## How it attacks (design)

- **LLM generates, varies and blends** the kill-chain; a deterministic engine
  grounds it and serves as offline fallback so a demo never hard-fails.
- **Evasion** (`redteam/evasion.py`): living-off-the-land binaries, style
  mimicry (shared users/paths with the benign noise), staged multi-command
  attacks where the *combination* is malicious, and positional blending so the
  20 malicious rows are spread across the timeline, never clustered.
- Works for **both Linux and Windows** and for **any scenario** the judges name.

## Architecture

```
redteam/
  cli.py          # argparse entry point
  generator.py    # orchestration, count-fixing, validation, CSV/story output
  llm_client.py   # provider-agnostic LLM call (Anthropic default, OpenAI), graceful fallback
  scenarios.py    # kill-chain scaffolds + generic fallback + deterministic render engine
  benign.py       # realistic benign command pools (Linux/Windows)
  evasion.py      # blending + obfuscation transforms
  story.py        # markdown attack narrative
```
