"""Provider-agnostic LLM client.

Defaults to Anthropic Claude (the bootcamp's recommended models); falls back
to OpenAI if only an OpenAI key is present. Reads the key from the
environment so you can paste whatever the 1Password item contains:

    export ANTHROPIC_API_KEY=sk-ant-...
    # or
    export OPENAI_API_KEY=sk-...

Any failure (missing key, SDK not installed, network/API error, bad JSON)
raises ``LLMUnavailable`` so the generator transparently uses the offline
deterministic engine instead — the live demo never hard-fails.
"""

from __future__ import annotations

import json
import os
import re

DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-8"
DEFAULT_OPENAI_MODEL = "gpt-4o"


class LLMUnavailable(RuntimeError):
    """Raised when no LLM call can be completed; caller should fall back."""


def _azure_key() -> str | None:
    for k in ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_KEY", "AZURE_OPENAI_MONITORING_KEY"):
        if os.environ.get(k):
            return os.environ[k]
    return None


def provider() -> str | None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if _azure_key() and os.environ.get("AZURE_OPENAI_ENDPOINT"):
        return "azure"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return None


def available() -> bool:
    return provider() is not None


def _extract_json(text: str):
    """Parse a JSON object/array from a model response, tolerating fences."""
    text = text.strip()
    # Strip ```json ... ``` fences if present.
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Last resort: grab the outermost [...] or {...}.
        for open_c, close_c in (("[", "]"), ("{", "}")):
            i, j = text.find(open_c), text.rfind(close_c)
            if i != -1 and j != -1 and j > i:
                try:
                    return json.loads(text[i:j + 1])
                except json.JSONDecodeError:
                    pass
    raise LLMUnavailable("Model did not return parseable JSON.")


def generate_json(system: str, user: str, model: str | None = None,
                  max_tokens: int = 8000):
    """Send a prompt and return parsed JSON, or raise LLMUnavailable."""
    prov = provider()
    if prov is None:
        raise LLMUnavailable("No ANTHROPIC_API_KEY or OPENAI_API_KEY set.")

    try:
        if prov == "anthropic":
            return _anthropic(system, user, model or DEFAULT_ANTHROPIC_MODEL, max_tokens)
        if prov == "azure":
            return _azure(system, user, model, max_tokens)
        return _openai(system, user, model or DEFAULT_OPENAI_MODEL, max_tokens)
    except LLMUnavailable:
        raise
    except Exception as exc:  # SDK/network/auth — fall back gracefully.
        raise LLMUnavailable(f"{prov} call failed: {exc}") from exc


def _anthropic(system: str, user: str, model: str, max_tokens: int):
    try:
        import anthropic
    except ImportError as exc:
        raise LLMUnavailable("anthropic SDK not installed (pip install anthropic).") from exc
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(block.text for block in resp.content if block.type == "text")
    return _extract_json(text)


def _openai(system: str, user: str, model: str, max_tokens: int):
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise LLMUnavailable("openai SDK not installed (pip install openai).") from exc
    client = OpenAI()
    resp = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return _extract_json(resp.choices[0].message.content)


def _azure(system: str, user: str, model: str | None, max_tokens: int):
    """Azure OpenAI: needs endpoint + deployment + api-version, not just a key."""
    try:
        from openai import AzureOpenAI
    except ImportError as exc:
        raise LLMUnavailable("openai SDK not installed (pip install openai).") from exc
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    deployment = model or os.environ.get("AZURE_OPENAI_DEPLOYMENT")
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-08-01-preview")
    if not endpoint or not deployment:
        raise LLMUnavailable(
            "Azure needs AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT.")
    client = AzureOpenAI(api_key=_azure_key(), azure_endpoint=endpoint,
                         api_version=api_version)
    resp = client.chat.completions.create(
        model=deployment,  # Azure uses the *deployment* name here, not a model id.
        max_tokens=max_tokens,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return _extract_json(resp.choices[0].message.content)
