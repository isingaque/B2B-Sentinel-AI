"""Optional OpenRouter free-model triage. Credentials never leave the backend.

The free router selects a compatible model dynamically; structured JSON is
requested but still validated locally, and any failure falls back to rules.
"""
import json

import httpx

from app.config import settings
from app.llm import SYSTEM_PROMPT, _redact, _validate_response

API_URL = "https://openrouter.ai/api/v1/chat/completions"


def classify_with_openrouter(alert: dict) -> dict:
    if not settings.openrouter_api_key:
        raise RuntimeError("missing_api_key")

    event = {
        "alert_name": _redact(alert.get("alert_name"), 180),
        "title": _redact(alert.get("title"), 320),
        "description": _redact(alert.get("description"), 1600),
    }
    response = httpx.post(
        API_URL,
        headers={
            "Authorization": "Bearer " + settings.openrouter_api_key,
            "Content-Type": "application/json",
        },
        json={
            "model": settings.openrouter_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(event, ensure_ascii=False)},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": 600,
            "stream": False,
        },
        timeout=httpx.Timeout(20.0, connect=5.0),
    )
    response.raise_for_status()
    envelope = response.json()
    choice = envelope["choices"][0]
    if choice.get("finish_reason") != "stop":
        raise ValueError("Incomplete OpenRouter response")
    text = choice["message"]["content"]
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Empty OpenRouter response")
    # Only structured fields are accepted; no executable instructions are used.
    return _validate_response(
        json.loads(text), "openrouter:" + settings.openrouter_model
    )
