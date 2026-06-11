"""Grade a detector's output against an answer key.

    ./.venv/bin/python testbench/score.py <answer_key.csv> <predictions.csv>

answer_key.csv : process_name,command_line,label        (from answer_key/)
predictions.csv: your detector's output. Two accepted shapes:
  1) full verdicts — has command_line + a verdict column (auto-detected from:
     verdict, label, prediction, pred, malicious, is_malicious, result, class).
     Values may be malicious/benign, 1/0, true/false, yes/no.
  2) flagged-only — pass --flagged-only: the file lists ONLY the commands your
     detector flagged malicious; everything else is treated as benign.

Matching is by command_line (whitespace-normalized). Prints the confusion
matrix, precision/recall/F1, and the bootcamp defender score (+1 TP, -1 FP).
"""

from __future__ import annotations

import argparse
import csv
import sys

VERDICT_COLS = ["verdict", "label", "prediction", "pred", "malicious",
                "is_malicious", "result", "class", "classification"]
MAL = {"malicious", "mal", "1", "true", "yes", "y", "bad", "attack", "suspicious"}
BEN = {"benign", "ben", "0", "false", "no", "n", "good", "normal", "clean"}


def _norm(cmd: str) -> str:
    return " ".join((cmd or "").split())


def _is_malicious(value: str) -> bool | None:
    v = (value or "").strip().lower()
    if v in MAL:
        return True
    if v in BEN:
        return False
    return None


def load_answer_key(path: str) -> dict[str, bool]:
    truth = {}
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            truth[_norm(row["command_line"])] = row["label"].strip().lower() == "malicious"
    return truth


def load_predictions(path: str, flagged_only: bool) -> dict[str, bool]:
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        fields = [f.lower() for f in (reader.fieldnames or [])]
        rows = list(reader)

    if flagged_only:
        # Every listed command is a malicious flag.
        return {_norm(r.get("command_line") or next(iter(r.values()))): True
                for r in rows}

    # Find the verdict column.
    col = next((c for c in VERDICT_COLS if c in fields), None)
    if col is None:
        sys.exit(f"[!] No verdict column found in {path}. Columns: {fields}\n"
                 f"    Expected one of {VERDICT_COLS}, or use --flagged-only.")
    # Map back to the original-cased key.
    orig = (reader.fieldnames or [])[fields.index(col)]
    preds = {}
    for r in rows:
        cmd = _norm(r.get("command_line") or "")
        verdict = _is_malicious(r.get(orig, ""))
        if verdict is None:
            verdict = False
        preds[cmd] = verdict
    return preds


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("answer_key")
    ap.add_argument("predictions")
    ap.add_argument("--flagged-only", action="store_true",
                    help="predictions file lists only the flagged-malicious commands")
    args = ap.parse_args()

    truth = load_answer_key(args.answer_key)
    preds = load_predictions(args.predictions, args.flagged_only)

    tp = fp = tn = fn = 0
    missing = 0
    unmatched_preds = [c for c in preds if c not in truth]
    for cmd, is_mal_truth in truth.items():
        pred_mal = preds.get(cmd)
        if pred_mal is None:
            # No prediction for this row -> treat as benign (not flagged).
            pred_mal = False
            missing += 1
        if is_mal_truth and pred_mal:
            tp += 1
        elif is_mal_truth and not pred_mal:
            fn += 1
        elif not is_mal_truth and pred_mal:
            fp += 1
        else:
            tn += 1

    total_mal = tp + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / total_mal if total_mal else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    defender = tp - fp           # bootcamp: +1 TP, -1 FP (TN/FN = 0), before speed/story
    attacker = (-tp) + fp + fn   # mirror: -1 TP, +1 FP, +1 FN

    print(f"Answer key : {args.answer_key}")
    print(f"Predictions: {args.predictions}")
    print("-" * 48)
    print(f"  True Positives  (caught malicious) : {tp:3d} / {total_mal}")
    print(f"  False Negatives (missed malicious) : {fn:3d}")
    print(f"  False Positives (benign flagged)   : {fp:3d}")
    print(f"  True Negatives  (benign ignored)   : {tn:3d}")
    print("-" * 48)
    print(f"  Precision : {precision:5.1%}   Recall : {recall:5.1%}   F1 : {f1:5.1%}")
    print(f"  Detection rate: {tp}/{total_mal} malicious caught")
    print("-" * 48)
    print(f"  Bootcamp DEFENDER score (TP - FP)  : {defender:+d}   (excl. speed & +20 story bonus)")
    print(f"  Implied ATTACKER score             : {attacker:+d}")
    if missing:
        print(f"\n  [i] {missing} answer-key rows had no matching prediction "
              f"(counted as benign/not-flagged).")
    if unmatched_preds:
        print(f"  [i] {len(unmatched_preds)} predictions didn't match any answer-key "
              f"command (ignored). Check command_line formatting.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
