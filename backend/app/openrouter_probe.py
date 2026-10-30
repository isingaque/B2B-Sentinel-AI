"""One real (potentially rate-limited) OpenRouter API call, without printing keys."""
import sys

import httpx

from app.config import settings
from app.openrouter import classify_with_openrouter


def main() -> int:
    if not settings.openrouter_api_key:
        print("FAIL: OPENROUTER_API_KEY is missing inside the worker container")
        return 2
    try:
        result = classify_with_openrouter({
            "alert_name": "PostgreSQLDown",
            "title": "PostgreSQL unavailable",
            "description": "The database service is not responding to connection attempts.",
        })
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        print("FAIL: OpenRouter HTTP", status)
        if status == 401:
            print("Check API key; it may be invalid or revoked.")
        elif status == 402:
            print("Check that a free model is selected and your account is eligible.")
        elif status == 429:
            print("Free-tier rate limit exceeded. Try later.")
        elif status == 400:
            print("Selected free model may not support JSON output. Try another model.")
        return 1
    except (httpx.RequestError, RuntimeError, ValueError, KeyError, IndexError, TypeError) as exc:
        print("FAIL: OpenRouter request/response error:", type(exc).__name__)
        return 1
    print("PASS: OpenRouter response received and validated")
    print("Model route:", result["model_version"])
    print("Category:", result["category"], "| severity:", result["severity"])
    print("A successful response does not prove accuracy or model stability.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
