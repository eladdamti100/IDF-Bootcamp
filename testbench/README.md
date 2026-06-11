# Detector Test Bench

A ready-made suite to check how good our Blue Team backend is. Feed it the
**unlabeled** inputs, let your detector flag malicious commands, then **grade**
the result against the hidden answer key.

```
testbench/
  unlabeled/      <- 12 CSVs, process_name,command_line ONLY  (feed these to your backend)
  answer_key/     <- same 12, WITH the label column           (the truth — don't feed these in)
  make_testbench.py  <- regenerate the suite
  score.py           <- grade your detector's output
```

Each dataset is 220 rows / exactly 20 malicious, across 8 scenarios and both
Linux & Windows, at mixed evasion levels (some heavily obfuscated). The scenario
is hidden from the detector — the filename slug is only for your bookkeeping.

## Workflow

1. **Run your detector** on a file in `unlabeled/`, e.g.
   `testbench/unlabeled/ransomware_linux.csv`.
2. **Save its output** as a CSV in one of two shapes:
   - **full verdicts** — `command_line` + a verdict column (any of: `verdict`,
     `label`, `prediction`, `malicious`, `result`…); values `malicious`/`benign`
     (also accepts `1`/`0`, `true`/`false`, `yes`/`no`).
   - **flagged-only** — just the rows you flagged malicious (pass `--flagged-only`).
3. **Grade it:**
   ```bash
   ./.venv/bin/python testbench/score.py \
       testbench/answer_key/ransomware_linux.csv \
       my_detector_output.csv
   # or, if you only list the flagged rows:
   ./.venv/bin/python testbench/score.py \
       testbench/answer_key/ransomware_linux.csv \
       my_flagged.csv --flagged-only
   ```

You get TP / FP / FN / TN, precision / recall / F1, and the bootcamp defender
score (`+1` per true positive, `-1` per false positive — speed penalty and the
`+20` story bonus are scored separately on the day).

Matching is by `command_line` (whitespace-normalized), so your output just needs
to preserve the command text from the input.

## Regenerate

```bash
./.venv/bin/python testbench/make_testbench.py
```

Deterministic (fixed seeds) so the answer key is stable. For a harder, varied
test, regenerate any single scenario with the live LLM:
```bash
set -a && . ./.env && set +a
python -m redteam "ransomware" --os linux --out ./out   # then use out/scored_*.csv + out/attack_*.csv
```
