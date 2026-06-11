"""Layer 3 — gray-zone LLM-as-JUDGE (bounded, hardened, uncrashable).

Guarantees:
  - QUOTA: the judge never sees more than LLM_QUOTA rows (single batched call).
  - KILL-SWITCH: if the time budget is exceeded, skip the LLM entirely.
  - INJECTION-HARDENED: prompt salting + role separation + neutralization (llmguard).
  - DEFENSIVE PARSER: any output (incl. garbage/injection echo) -> valid verdicts.
  - FP-SAFE DEFAULT: unknown/missing/over-budget -> benign (FP costs 2 pts, FN 0).

llm_fn(system:str, user:str, max_tokens:int, timeout:float) -> str is injected.
Backends below: Azure OpenAI, Anthropic. If None -> offline (gray -> benign).
"""
import json
from . import llmguard

LLM_QUOTA = 25
TIME_BUDGET = 4.0  # seconds of wall-clock before we refuse to call the LLM


def resolve_gray_zone(gray_rows, elapsed, llm_fn=None, log=print):
    """Return {idx: (verdict, technique_or_None)} for the gray-zone rows."""
    if elapsed > TIME_BUDGET:
        log(f"[kill-switch] {elapsed:.1f}s > {TIME_BUDGET}s budget -> LLM skipped, heuristics-only")
        return {r["idx"]: ("benign", None) for r in gray_rows}

    if llm_fn is None:
        log("[judge] offline mode (no llm_fn) -> gray zone defaults benign (FP-safe)")
        return {r["idx"]: ("benign", None) for r in gray_rows}

    # QUOTA: only the top-K most suspicious reach the judge
    ranked = sorted(gray_rows, key=lambda r: r["score"], reverse=True)[:LLM_QUOTA]
    dropped = len(gray_rows) - len(ranked)
    if dropped > 0:
        log(f"[judge] gray zone {len(gray_rows)} > quota {LLM_QUOTA}; {dropped} lowest default benign")

    result = {r["idx"]: ("benign", None) for r in gray_rows}  # FP-safe base
    system, user, _salt = llmguard.build_judge_messages(ranked)
    try:
        raw = llm_fn(system, user, max_tokens=14 * len(ranked) + 48, timeout=2.5)
        verdicts = llmguard.parse_judge(raw, ranked)
    except Exception as e:
        log(f"[judge] LLM call failed ({type(e).__name__}) -> fallback benign for {len(ranked)} rows")
        return result

    for r in ranked:
        v, tech, inj = verdicts.get(r["idx"], ("benign", None, False))
        if inj:  # the row tried to manipulate the judge -> malicious by definition
            v, tech = "malicious", (tech or "T1027")
            log(f"[judge] row {r['idx']}: prompt-injection attempt detected -> malicious")
        result[r["idx"]] = (v, tech)
    return result


# ============================ LLM backends ============================

def azure_openai_llm_factory(api_key, endpoint, deployment="gpt-4o-mini",
                             api_version="2024-10-21"):
    """Azure OpenAI Chat Completions backend (stdlib urllib, no SDK).
    Forces JSON-object output (response_format) for a stable, parseable shape."""
    import urllib.request
    base = endpoint.rstrip("/")

    def _fn(system, user, max_tokens, timeout):
        url = f"{base}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
        body = json.dumps({
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "max_tokens": max_tokens,
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"api-key": api_key, "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    return _fn


def anthropic_llm_factory(api_key, model="claude-haiku-4-5-20251001"):
    """Anthropic Messages backend (stdlib urllib, no SDK)."""
    import urllib.request

    def _fn(system, user, max_tokens, timeout):
        body = json.dumps({
            "model": model,
            "max_tokens": max_tokens,
            "temperature": 0,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "stop_sequences": ["```"],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=body,
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        return "".join(b.get("text", "") for b in data.get("content", []))

    return _fn
