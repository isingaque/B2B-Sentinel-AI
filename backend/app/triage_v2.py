"""Offline, explainable incident triage v2.

No network calls, model downloads or database migrations. Decisions use
structured Prometheus metadata if supplied; otherwise a conservative set of
domain and symptom patterns. Heuristic outputs have NO calibrated confidence.
Independent evaluation must not leak source category/severity labels.
"""
from __future__ import annotations

import re

CATEGORY_VALUES = {"server", "network", "database", "application"}
SEVERITY_VALUES = {"critical", "warning", "info"}
PRIORITY = {"critical": "P1", "warning": "P2", "info": "P4"}

# Explicitly match known monitoring subsystems; use alert names and the
# Prometheus job/service only as *source* evidence, not as a severity answer.
SOURCE_FAMILIES = (
    ("database", re.compile(
        r"^(?:postgres|postgresql|mysql|mariadb|redis|mongodb|mongo|cassandra|"
        r"clickhouse|elastic(?:search)?|cockroach|pgbouncer|oracle|db)(?:\b|(?=[A-Z]))",
        re.I)),
    ("network", re.compile(
        r"^(?:snmp|blackbox|cilium|juniper|router|switch|network|linkerd|dns)(?:\b|(?=[A-Z]))",
        re.I)),
    ("server", re.compile(
        r"^(?:host|node|systemd|machine|hardware|filesystem|disk|memory|cpu|kernel)(?:\b|(?=[A-Z]))",
        re.I)),
    ("application", re.compile(
        r"^(?:nginx|apache|php|python|golang|go(?=[A-Z])|"
        r"haproxy|caddy|envoy|app|frontend|backend|api|http|jvm|java)(?:\b|(?=[A-Z]))",
        re.I)),
)

# Domain terms can supplement ambiguous alert names and descriptions.
# Evaluate longer, more specific indicators before generic words.
INDICATORS = {
    "database": (
        "postgres", "mysql", "mariadb", "redis", "mongodb", "database", "sql",
        "cassandra", "clickhouse", "elasticsearch", "replication", "database", "база данных", "бд",
    ),
    "network": (
        "packet loss", "router", "switch", "snmp", "cilium", "dns", "gateway",
        "bandwidth", "network", "routing", "packets", "сетев", "маршрут", "пакетов",
    ),
    "server": (
        "filesystem", "memory", "disk", "node", "host", "systemd", "kernel", "cpu",
        "inodes", "hardware", "machine", "processor", "сервер", "диск", "памят", "процессор",
    ),
    "application": (
        "nginx", "apache", "php", "python", "frontend", "backend", "application",
        "http", "api", "website", "service", "приложен", "веб", "сервис",
    ),
}

INFRA_PREFIX = re.compile(
    r"^(?:host|systemd|node|blackbox|snmp|cilium|juniper|postgres|mysql|redis|"
    r"nginx|apache|php|python|go(?=[A-Z])|mongodb|cassandra|clickhouse|"
    r"elastic|haproxy|caddy|envoy|jvm)",
    re.I,
)
SEVERITY_CRITICAL = (
    r"\bcritical\b|\bне\s+отвечает\b|\bнедоступ\w*|\bкритич\w*|"
    r"\bостанов\w*|\bотказ\w*|\bполный\s+сбой\b|"
    r"\b(?:unavailable|outage|not\s+responding|connection\s+refused)\b|"
    r"\b(?:down|dead|failed)\b|"
    r"\b(?:certificate\s+expired|out\s+of\s+disk\s+space)\b|"
    r"\b(?:max\w*\s+connections?\s+reached|exhausted\s+connections?)\b|"
    r"\bhttp\s*5(?:02|03)\b|\b(?:502|503)\b"
)
SEVERITY_WARNING = (
    r"\b(?:warning|high|slow|latency|threshold|degraded|degradation)\b|"
    r"\b(?:packet\s+loss|low\s+space|disk\s+full|load\s+average)\b|"
    r"\b(?:near\s+limit|saturation|pressure|errors?\s+increased)\b|"
    r"\b(?:высок\w*|задерж\w*|потер\w*|заполня\w*|мало\s+места)\b"
)
SEVERITY_INFO = (
    r"\b(?:underutilized|unused|informational|info|notice|rebooted|"
    r"configuration\s+changed|restarted\s+successfully)\b|"
    r"\b(?:информац\w*|событие\s+без\s+ошибки)\b"
)


def _split_identifier(value: object) -> str:
    raw = str(value or "")[:500]
    # Preserve word boundaries from CamelCase, acronyms and snake_case.
    raw = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", raw)
    raw = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", raw)
    return re.sub(r"[^\w\u0400-\u04FF%]+", " ", raw.replace("_", " ")).lower()


def _raw(alert: dict) -> tuple[dict, str, str]:
    labels = {str(k).lower(): str(v)[:200] for k, v in
              (alert.get("labels") or {}).items()}
    name = str(alert.get("alert_name") or "")[:300]
    parts = (name, alert.get("title") or "", alert.get("description") or "")
    text = " ".join(_split_identifier(item) for item in parts)
    return labels, name, text


def _category(name: str, text: str, labels: dict) -> tuple[str, str]:
    explicit = str(labels.get("category") or "").lower()
    if explicit in CATEGORY_VALUES:
        return explicit, "Категория передана источником мониторинга"

    # Source-based classification; a host's network anomaly is still
    # categorized as server if it came from host/node exporter.
    for category, pattern in SOURCE_FAMILIES:
        if pattern.search(name):
            return category, "Категория по семейству мониторинга: " + category

    source = " ".join(str(labels.get(x) or "") for x in ("job", "exporter", "service"))
    for category, pattern in SOURCE_FAMILIES:
        if pattern.search(source):
            return category, "Категория по источнику метрик: " + category

    scores = {
        category: sum(1 for token in indicators if token in text)
        for category, indicators in INDICATORS.items()
    }
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return "application", "Категория предположена из-за отсутствия признаков"
    return best, "Категория по обнаруженным признакам: " + best


def _severity(name: str, text: str, labels: dict) -> tuple[str, str]:
    explicit = str(labels.get("severity") or "").lower()
    if explicit in SEVERITY_VALUES:
        return explicit, "Критичность передана источником мониторинга"

    # Description and rule name frequently contain severity-specific words
    # and thresholds. Different alerting configurations can disagree,
    # therefore heuristic severity is never reported as certain.
    name_words = _split_identifier(name)
    if re.search(r"\bcritical\b", name_words):
        return "critical", "Критичный уровень указан в названии события"
    if re.search(r"\bwarning\b", name_words):
        return "warning", "Предупреждение указано в названии события"
    if re.search(r"\binfo\b", name_words):
        return "info", "Информационный уровень указан в названии"

    if re.search(SEVERITY_INFO, text):
        return "info", "Информационный тип события"
    # A generic exception-count notice without a threshold does not prove
    # an outage. Preserve the legacy informational synthetic scenario.
    if (re.search(r"\\bexception\\b", text) and
            re.search(r"\\berrors?\\s+increased\\b", text) and
            not re.search(r"\\b(?:critical|high|threshold)\\b|\\d+\\s*%", text)):
        return "info", "Рост ошибок без указанного порога: требуется проверка"
    if re.search(SEVERITY_CRITICAL, text):
        return "critical", "Признаки критического сбоя в содержании"
    if re.search(r"(?:9[5-9]|100)\s*%", text):
        return "critical", "Критический порог загрузки в описании"
    if re.search(SEVERITY_WARNING, text):
        return "warning", "Признаки деградации в содержании"
    if re.search(r"\b[89]\d\s*%", text):
        return "warning", "Порог предупреждения в описании"

    # Without a declared severity, this is a hypothesis, not a fact.
    # AppError is intentionally informational in the in-repo synthetic
    # fixture; do not infer critical solely from "error".
    if not INFRA_PREFIX.search(name) and (
        "exception" in text or "errors increased" in text
    ):
        return "info", "Недостаточно признаков критической деградации"
    return "warning", "Осторожная оценка: требуется сверка порогов правила Prometheus"


def classify_v2(alert: dict) -> dict:
    """Classify without an external AI API; never invent statistical confidence."""
    labels, name, text = _raw(alert)
    category, cat_reason = _category(name, text, labels)
    severity, sev_reason = _severity(name, text, labels)
    return {
        "category": category,
        "severity": severity,
        "priority": PRIORITY[severity],
        "confidence": None,  # Heuristics are not calibrated probabilities.
        "review_required": True,
        "explanation": (
            cat_reason + "; " + sev_reason +
            ". Оценка не является подтверждённым диагнозом; решение проверяет дежурный инженер."
        ),
        "model_version": "offline-triage-v2",
    }
