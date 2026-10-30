"""Free OpenRouter provider unit tests; no network traffic or actual keys."""
import json

import httpx
import pytest

from app import llm, openrouter


EVENT = {"alert_name": "PostgreSQLDown", "title": "Database unavailable",
         "description": "Database connection refused", "labels": {"instance": "private-host"}}


def configure(monkeypatch, key="fake-test-key"):
    monkeypatch.setattr(llm.settings, "ai_provider", "openrouter")
    monkeypatch.setattr(llm.settings, "openrouter_api_key", key)
    monkeypatch.setattr(llm.settings, "openrouter_model", "openrouter/free")


def response(status=200, payload=None):
    if payload is None:
        payload = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps({
            "category": "database", "severity": "critical",
            "explanation": "PostgreSQL is unreachable",
            "probable_causes": ["Database service unavailable"],
        })}}]}
    return httpx.Response(status, request=httpx.Request("POST", openrouter.API_URL), json=payload)


def test_free_route_sends_limited_info_and_parses_json(monkeypatch):
    configure(monkeypatch)
    calls = []
    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return response()
    monkeypatch.setattr(openrouter.httpx, "post", fake_post)
    result = llm.classify_incident(EVENT)
    assert result["model_version"] == "openrouter:openrouter/free"
    assert result["category"] == "database"
    assert result["severity"] == "critical"
    assert result["priority"] == "P1"
    assert result["confidence"] is None
    assert result["review_required"]
    assert len(calls) == 1
    url, kwargs = calls[0]
    assert url == "https://openrouter.ai/api/v1/chat/completions"
    assert kwargs["json"]["model"] == "openrouter/free"
    assert kwargs["json"]["response_format"] == {"type": "json_object"}
    assert "thinking" not in kwargs["json"]
    assert "private-host" not in kwargs["json"]["messages"][1]["content"]


def test_missing_key_falls_back(monkeypatch):
    configure(monkeypatch, "")
    monkeypatch.setattr(openrouter.httpx, "post", lambda *a, **kw: pytest.fail("Should not call API"))
    result = llm.classify_incident(EVENT)
    assert result["model_version"] == "expert-rules-v1+fallback"
    assert "ключ не задан" in result["explanation"]


def test_openrouter_limit_falls_back(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(openrouter.httpx, "post", lambda *a, **kw: response(429, {"error": {"message": "rate limit"}}))
    result = llm.classify_incident(EVENT)
    assert result["model_version"] == "expert-rules-v1+fallback"
    assert "429" in result["explanation"]


def test_nonjson_reply_falls_back(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(openrouter.httpx, "post", lambda *a, **kw: response(
        200, {"choices": [{"finish_reason": "stop", "message": {"content": "Not JSON"}}]}))
    result = llm.classify_incident(EVENT)
    assert result["model_version"] == "expert-rules-v1+fallback"


def test_invalid_category_falls_back(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(openrouter.httpx, "post", lambda *a, **kw: response(
        200, {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(
            {"category": "unspecified", "severity": "critical", "explanation": "Unknown"})}}]}))
    result = llm.classify_incident(EVENT)
    assert result["model_version"] == "expert-rules-v1+fallback"
