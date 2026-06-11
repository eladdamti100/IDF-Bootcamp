"""Command-line interface: `python -m redteam "<scenario>" [options]`."""

from __future__ import annotations

import argparse
import sys

from . import __version__, generator, llm_client


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="redteam",
        description="Generate a realistic process-command attack dataset "
                    "(~220 rows, exactly 20 malicious) plus ground truth and a story.",
    )
    p.add_argument("scenario", help="Scenario to generate, e.g. 'ransomware', "
                                    "'lateral movement', 'crypto miner'.")
    p.add_argument("--os", dest="os_name", choices=["linux", "windows"],
                   default="linux", help="Target OS (default: linux).")
    p.add_argument("--out", default="./out", help="Output directory (default: ./out).")
    p.add_argument("--total", type=int, default=220, help="Total rows (default: 220).")
    p.add_argument("--malicious", type=int, default=20,
                   help="Number of malicious commands (default: 20).")
    p.add_argument("--seed", type=int, default=1337,
                   help="Seed for reproducible generation (default: 1337).")
    p.add_argument("--evasion", type=int, choices=[0, 1, 2], default=1,
                   help="Obfuscation level: 0=none, 1=light, 2=aggressive (default: 1).")
    p.add_argument("--model", default=None, help="Override LLM model id.")
    p.add_argument("--no-llm", action="store_true",
                   help="Skip the LLM and use the deterministic offline engine.")
    p.add_argument("--version", action="version", version=f"redteam {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    use_llm = not args.no_llm
    if use_llm and not llm_client.available():
        print("[!] No ANTHROPIC_API_KEY / OPENAI_API_KEY found — using offline "
              "engine. (Set a key to use the LLM, or pass --no-llm to silence this.)",
              file=sys.stderr)
        use_llm = False

    result = generator.generate(
        scenario=args.scenario, os_name=args.os_name, total=args.total,
        n_malicious=args.malicious, seed=args.seed, use_llm=use_llm,
        model=args.model, evasion_level=args.evasion,
    )
    paths = generator.write_outputs(result, args.out)

    print(f"Scenario      : {args.scenario}  (matched: {result.scenario_key})")
    print(f"OS / rows     : {result.os_name} / {result.total} "
          f"({len(result.malicious)} malicious)")
    print(f"Source        : malicious={result.sources['malicious']}, "
          f"benign={result.sources['benign']}")
    print("Outputs:")
    print(f"  attack CSV  : {paths['attack']}  (labeled, internal)")
    print(f"  scored CSV  : {paths['scored']}  (no label — feed to detector)")
    print(f"  ground truth: {paths['ground_truth']}  (submit to judges)")
    print(f"  attack story: {paths['story']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
