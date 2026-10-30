"""Tests for the optional DeepSeek path. No real API key or network required."""
import json

import httpx
import pytest

from app import llm
from app.ai import classify


EVENT = {
    "alert_name": "PostgreSQLDown",
    "title": "Database unreachable",
    "description": "Connections refused by database service",
    "labels": {"category": "network", "severity": "info", "instance": "private-node"},
}


def _enable(monkeypatch, key="fake-local-test-key"):
    monkeypatch.setattr(llm.settings, "ai_provider", "deepseek")
    monkeypatch.setattr(llm.settings, "deepseek_api_key", key)
    monkeypatch.setattr(llm.settings, "deepseek_model", "deepseek-flash")


def _response(status=200, body=None):
    request = httpx.Request("POST", llm.API_URL)
    if body is None:
        body = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps({
            "category": "database",
            "severity": "critical",
            "explanation": "Database is not responding",
            "probable_causes": ["Connection pool unavailable"],
        })}}]}
    return httpx.Response(status, request=request, json=body)


def test_default_mode_never_calls_external_api(monkeypatch):
    monkeypatch.setattr(llm.settings, "ai_provider", "rules")
    monkeypatch.setattr(llm.settings, "deepseek_api_key", "")
    monkeypatch.setattr(llm.httpx, "post", lambda *a, **kw: pytest.fail("Network call in local mode"))
    assert llm.classify_incident(EVENT) == classify(EVENT)


def test_deepseek_valid_json_and_untrusted_labels_are_not_sent(monkeypatch):
    _enable(monkeypatch)
    requests = []

    def fake_post(url, **kwargs):
        requests.append((url, kwargs))
        return _response()

    monkeypatch.setattr(llm.httpx, "post", fake_post)
    result = llm.classify_incident(EVENT)
    assert result["model_version"] == "deepseek:deepseek-flash"
    assert result["category"] == "database"
    assert result["severity"] == "critical"
    assert result["priority"] == "P1"
    assert result["confidence"] is None
    assert result["review_required"] is True
    assert "Гипотеза" in result["explanation"]
    assert len(requests) == 1
    url, args = requests[0]
    assert url == "https://api.deepseek.com/chat/completions"
    assert args["json"]["response_format"]["type"] == "json_object"
    user_input = args["json"]["messages"][1]["content"]
    assert "private-node" not in user_input
    assert '"severity"' not in user_input
    assert '"category"' not in user_input


def test_missing_key_falls_back_without_network(monkeypatch):
    _enable(monkeypatch, key="")
    monkeypatch.setattr(llm.httpx, "post", lambda *a, **kw: pytest.fail("Unexpected API call"))
    result = llm.classify_incident(EVENT)
    assert result["model_version"] == "expert-rules-v1+fallback"
    assert result["confidence"] == classify(EVENT)["confidence"]


def test_http_401_falls_back_and_never_persists_key(monkeypatch):
    _enable(monkeypatch, key="very-secret-key-for-test")
    monkeypatch.setattr(llm.httpx, "post", lambda *a, **kw: _response(401, {"error": {"message": "Bad auth"}}))
    result = llm.classify_incident(EVENT)
    assert result["model_version"] == "expert-rules-v1+fallback"
    assert "HTTP 401" in result["explanation"]
    assert "very-secret-key-for-test" not in str(result)


def test_invalid_classification_falls_back(monkeypatch):
    _enable(monkeypatch)
    response = _response(body={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps({
        "category": "other", "severity": "extreme", "explanation": "unrecognised"
    })}}]})
    monkeypatch.setattr(llm.httpx, "post", lambda *a, **kw: response)
    result = llm.classify_incident(EVENT)
    assert result["model_version"] == "expert-rules-v1+fallback"


def test_secret_redaction():
    text = "Bearer abc123 password=1234 token=hidden sk-abcdefghijklmnop"
    redacted = llm._redact(text)
    assert "abc123" not in redacted
    assert "1234" not in redacted
    assert "hidden" not in redacted
    assert "sk-abcdefghijklmnop" not in redacted
