"""Explainable local classifier + retrieval. No external actions or unverified instructions."""
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from math import sqrt
import re
from app.config import settings

KEYWORDS = {
    "database": ("postgres", "mysql", "database", "db down", "sql", "redis down", "баз данных", "бд", "репликац", "query", "connection refused"),
    "network": ("packet loss", "network", "latency", "dns", "ping", "router", "gateway", "interface", "пакет", "сетев", "маршрут", "соединен"),
    "server": ("cpu", "memory", "ram", "disk", "filesystem", "storage", "load average", "inode", "server", "сервер", "диск", "памят", "процессор"),
    "application": ("nginx", "http", "502", "503", "api", "frontend", "app", "service down", "backend", "exception", "application", "приложен", "веб", "сервис"),
}
HIGH = ("down", "unavailable", "connection refused", "not responding", "critical", "outage", "95%", "502", "503", "недоступ", "отказ", "не отвечает", "упал", "критич")
MED = ("high", "warning", "slow", "threshold", "latency", "90%", "packet loss", "мало", "высок", "задерж", "потер")

def classify(alert: dict) -> dict:
    labels = alert.get("labels") or {}
    raw_text = " ".join([str(alert.get("alert_name", "")), str(alert.get("title", "")), str(alert.get("description", "")), " ".join(str(v) for v in labels.values())]).lower()
    explicit_category = str(labels.get("category", "")).lower()
    scores = {cat: sum(1 for word in words if word in raw_text) for cat, words in KEYWORDS.items()}
    if explicit_category in KEYWORDS:
        category, category_conf = explicit_category, .99
        category_expl = f"category задана Prometheus: {explicit_category}"
    else:
        category = max(scores, key=scores.get)
        if scores[category] == 0:
            category = "application"
            category_conf = .35
        else:
            category_conf = min(.94, .62 + scores[category] * .09)
        category_expl = f"ключевые признаки {category}: {scores[category]}"
    explicit_severity = str(labels.get("severity", "")).lower()
    if explicit_severity in ("critical", "warning", "info"):
        severity, sev_conf = explicit_severity, .99
        sev_expl = f"severity задана Prometheus: {severity}"
    else:
        if any(word in raw_text for word in HIGH):
            severity = "critical"
        elif any(word in raw_text for word in MED):
            severity = "warning"
        else:
            severity = "info"
        sev_conf = .78 if severity != "info" else .55
        sev_expl = f"оценка уровня по описанию: {severity}"
    priority = {"critical": "P1", "warning": "P2", "info": "P4"}[severity]
    confidence = round(min(category_conf, sev_conf), 2)
    return {"severity": severity, "category": category, "priority": priority,
            "confidence": confidence, "review_required": confidence < .8,
            "explanation": f"{category_expl}; {sev_expl}. Уровень уверенности не гарантирует корректность — решение проверяет инженер.",
            "model_version": "expert-rules-v1"}

def tokens(text: str):
    return set(re.findall(r"[a-zа-яё0-9]{3,}", text.lower()))

@lru_cache(maxsize=1)
def _e5():
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer("intfloat/multilingual-e5-small")

def embed(text: str, kind: str = "passage") -> list[float]:
    if settings.embedding_backend == "e5":
        # E5 convention requires query/passage prefixes. Model is opt-in; downloads on first use.
        arr = _e5().encode(f"{kind}: {text}", normalize_embeddings=True)
        return [float(v) for v in arr]
    # No downloads required: multilingual character-ngram feature hashing in 384 dimensions.
    normalized = re.sub(r"\s+", " ", text.lower().strip())
    vec = [0.0] * 384
    for token in tokens(normalized):
        for fragment in ([token] + [token[i:i+3] for i in range(max(0, len(token)-2))]):
            h = sha256(fragment.encode("utf-8")).digest()
            pos = int.from_bytes(h[:4], "big") % 384
            vec[pos] += 1.0
    length = sqrt(sum(x*x for x in vec))
    return [x / length for x in vec] if length else vec

def lexical_score(query: str, document: str) -> float:
    a, b = tokens(query), tokens(document)
    if not a or not b:
        return 0.0
    return len(a & b) / sqrt(len(a) * len(b))

def pick_runbooks(alert: dict, classified: dict, runbooks: list) -> list[tuple]:
    query = " ".join([alert.get("alert_name", ""), alert.get("title", ""), alert.get("description", ""), " ".join(alert.get("labels", {}).values())])
    v = embed(query, "query")
    ranking = []
    for runbook in runbooks:
        if not runbook.is_active:
            continue
        if runbook.category and runbook.category != classified["category"]:
            continue
        # A runbook valid for a given category can apply at different severities; prefer an exact match.
        doc = runbook.title + " " + runbook.condition_text
        existing_embedding = runbook.embedding if runbook.embedding is not None else embed(doc)
        dense = float(sum(float(x)*float(y) for x,y in zip(v, existing_embedding)))
        lexical = lexical_score(query, doc)
        severity_bonus = .09 if runbook.severity == classified["severity"] else 0
        score = min(1.0, max(0.0, .53 * max(0, dense) + .38 * lexical + severity_bonus))
        if score >= .13:
            ranking.append((runbook, round(score, 3), f"Похожесть сигнала и регламента: {score:.2f}; категория {classified['category']}."))
    return sorted(ranking, key=lambda x:x[1], reverse=True)[:3]
