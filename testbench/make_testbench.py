"""Build a detector test bench.

For each (scenario, os) pair, generates a 220-row dataset and writes:
  - unlabeled/<name>.csv    -> process_name,command_line   (feed to your detector)
  - answer_key/<name>.csv   -> process_name,command_line,label  (grade against)

Uses the deterministic offline engine (use_llm=False) so the bench is
reproducible: same seed -> same data -> stable answer key. Regenerate any
single scenario with the LLM (harder/varied) via `python -m redteam ...`.

Run:  ./.venv/bin/python testbench/make_testbench.py
"""

from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from redteam import generator  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
UNLABELED = os.path.join(HERE, "unlabeled")
ANSWER_KEY = os.path.join(HERE, "answer_key")

# (scenario, os, seed, evasion_level). Mixed OS and evasion to stress the
# detector from several angles.
BENCH = [
    ("ransomware", "linux", 11, 1),
    ("crypto miner", "linux", 22, 1),
    ("lateral movement", "linux", 33, 2),
    ("data exfiltration", "linux", 44, 1),
    ("persistence", "linux", 55, 1),
    ("privilege escalation", "linux", 66, 2),
    ("credential access", "linux", 77, 1),
    ("backdoor", "linux", 88, 2),
    ("ransomware", "windows", 111, 1),
    ("lateral movement", "windows", 122, 1),
    ("credential access", "windows", 133, 2),
    ("persistence", "windows", 144, 1),
]


def _slug(scenario: str, os_name: str) -> str:
    s = "".join(c if c.isalnum() else "-" for c in scenario.strip().lower()).strip("-")
    return f"{s}_{os_name}"


def main() -> int:
    os.makedirs(UNLABELED, exist_ok=True)
    os.makedirs(ANSWER_KEY, exist_ok=True)
    manifest = []
    for scenario, os_name, seed, evasion in BENCH:
        result = generator.generate(
            scenario=scenario, os_name=os_name, seed=seed,
            use_llm=False, evasion_level=evasion,
        )
        name = _slug(scenario, os_name)

        with open(os.path.join(UNLABELED, f"{name}.csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["process_name", "command_line"])
            w.writeheader()
            for r in result.rows:
                w.writerow({"process_name": r["process_name"],
                            "command_line": r["command_line"]})

        with open(os.path.join(ANSWER_KEY, f"{name}.csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["process_name", "command_line", "label"])
            w.writeheader()
            for r in result.rows:
                w.writerow({k: r[k] for k in ["process_name", "command_line", "label"]})

        manifest.append((name, scenario, os_name, evasion))
        print(f"  {name:34} scenario={scenario:22} os={os_name:7} evasion={evasion}")

    print(f"\nWrote {len(manifest)} datasets to:")
    print(f"  inputs (no label) : {UNLABELED}")
    print(f"  answer key        : {ANSWER_KEY}")
    print("\nThe scenario for each file is hidden from your detector — the slug in the\n"
          "filename is only for YOUR bookkeeping. Use score.py to grade results.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
