"""Optional one-request DeepSeek connectivity probe; no credentials in output.

Run only after setting AI_PROVIDER=deepseek and DEEPSEEK_API_KEY in .env:
  docker compose exec worker python -m app.deepseek_probe
This is a billable API call and does not touch the incident database.
"""
import sys

import httpx

from app.config import settings
from app.llm import classify_with_deepseek


def main():
    if not settings.deepseek_api_key:
        print("FAIL: DEEPSEEK_API_KEY is missing inside the worker container")
        return 2
    try:
        result = classify_with_deepseek({
            "alert_name": "PostgreSQLDown",
            "title": "PostgreSQL connection refused",
            "description": "The database is unreachable and connection attempts fail.",
        })
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        print("FAIL: DeepSeek HTTP", status)
        if status == 401:
            print("Check the API key; it may be invalid or revoked.")
        elif status in (402, 403):
            print("Check API account balance, subscription and access.")
        elif status == 429:
            print("API rate limit reached.")
        return 1
    except (httpx.RequestError, ValueError, KeyError, RuntimeError) as exc:
        print("FAIL: DeepSeek request or response error:", type(exc).__name__)
        return 1
    print("PASS: DeepSeek response received and validated")
    print("Model:", result["model_version"])
    print("Category:", result["category"], "| severity:", result["severity"])
    print("This does NOT measure classification accuracy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
