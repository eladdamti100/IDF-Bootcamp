#!/usr/bin/env python3
"""Run the GLASSBOX engine across every unlabeled testbench CSV and emit a
predictions CSV (command_line,verdict) per file for grading with score.py.

Usage:
    python testbench/run_glassbox.py [--llm] [--threat-intel] [--out DIR]
"""
import argparse
import csv
import glob
import os
import sys
from time import monotonic

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from glassbox import pipeline  # noqa: E402


def backend(use_llm):
    if not use_llm:
        return None
    from server import select_backend  # reuse env + backend selection
    return select_backend(lambda *_: None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--threat-intel", action="store_true")
    ap.add_argument("--out", default=os.path.join(HERE, "_preds"))
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    llm_fn = backend(args.llm)
    files = sorted(glob.glob(os.path.join(HERE, "unlabeled", "*.csv")))

    print(f"{'dataset':30} {'flagged':>7} {'scenario guess':28} {'time':>7}")
    print("-" * 78)
    rows_meta = []
    for f in files:
        name = os.path.basename(f)
        is_windows = "_windows" in name or name.endswith("windows.csv")
        with open(f, encoding="utf-8") as fh:
            raw = fh.read()
        t0 = monotonic()
        res = pipeline.analyze_csv(raw, llm_fn=llm_fn, is_windows=is_windows,
                                   threat_intel=args.threat_intel, log=lambda *_: None)
        dt = monotonic() - t0
        out_path = os.path.join(args.out, name)
        with open(out_path, "w", newline="", encoding="utf-8") as out:
            w = csv.writer(out)
            w.writerow(["command_line", "verdict"])
            for r in res["rows"]:
                w.writerow([r["command_line"], r["verdict"]])
        sc = res["story"]["scenario"]
        print(f"{name:30} {res['counts']['malicious']:>7} {sc[:28]:28} {dt:6.3f}s")
        rows_meta.append((name, sc))

    print(f"\npredictions written to {args.out}")


if __name__ == "__main__":
    main()
