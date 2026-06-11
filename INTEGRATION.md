# Blue Shield dashboard × GLASSBOX engine

The dashboard (`blue-shield-dashboard.html`) now runs on the **GLASSBOX** detection
engine via a small same-origin Flask backend (`server.py`). The LLM judge runs
**server-side**, so no API key is exposed in the browser.

## Run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python server.py            # http://127.0.0.1:5001
```

Open http://127.0.0.1:5001, drop a CSV, keep **🛡️ GLASSBOX Engine** selected, Start AI Scan.

## What changed

- **`server.py`** — serves the dashboard + JSON API:
  - `POST /api/detect` — `{rows:[{process_name,command_line}], options}` → per-row
    verdicts, suspicion score, MITRE technique, reasons, and the kill-chain story/scenario.
  - `POST /api/assistant` — SOC-analyst chat grounded in the current scan (Azure).
  - `GET /api/health` — LLM backend availability (badge in the header).
- **`glassbox/`** — the detection engine package (normalize → signatures → heuristic
  score → threat-intel → LLM-as-judge → MITRE kill-chain story).
- **dashboard** — added a third Detection Engine option, **GLASSBOX Engine**
  (default). `detectThreatsWithGlassbox()` calls `/api/detect` and returns the
  same row shape the UI already renders, so the existing story/scenario/phase/table
  panels work unchanged. The Mock and Claude engines are still available.

## Engine options (under the dropdown, GLASSBOX only)

- **AI judge (gray-zone)** — server-side LLM verifies only the ambiguous rows. Off by
  default (faster, precision-first; speed is `−1/sec` in the rubric).
- **Threat-intel (live)** — abuse.ch URLhaus lookups, off the scored hot path.
- **Windows / Linux** — controls normalization.

## Config

`.env` (git-ignored) holds the Azure OpenAI creds:

```
AZURE_OPENAI_MONITORING_KEY=...
AZURE_OPENAI_ENDPOINT=https://<resource>.cognitiveservices.azure.com/
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_API_VERSION=2024-10-21
```

No creds → the engine runs fully offline (deterministic core, still fast and precise).

> Rotate the Azure key after the event — it was shared in plaintext.

See `DOCUMENTATION.md`-level detail in the original GLASSBOX repo for the full
technique/score/attention write-up.
