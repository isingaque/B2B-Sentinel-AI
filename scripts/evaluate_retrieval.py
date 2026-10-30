"""Evaluate approved seed runbook retrieval on human-authored paraphrases.

Does not read, reset or mutate PostgreSQL. Use hash by default; E5 is
optional and requires INSTALL_E5=1 and model download.
"""
import argparse
import json
from pathlib import Path
from types import SimpleNamespace

from app.ai import embed, pick_runbooks
from app.bootstrap import SEEDS
from app.config import settings

# Human-authored probes; these are not industrial tickets and not a holdout.
# They intentionally include lexical and paraphrased variants.
PROBES = [
    ("server", "critical", "cpu", "Процессор загружен выше 95 процентов"),
    ("server", "critical", "cpu", "CPU utilization is very high on the host"),
    ("server", "critical", "cpu", "На узле наблюдается полная загрузка процессора"),
    ("server", "warning", "disk", "На разделе сервера заканчивается свободное место"),
    ("server", "warning", "disk", "Filesystem has almost no free space left"),
    ("server", "warning", "disk", "Диск заполнен, необходимо проверить лог-файлы"),
    ("database", "critical", "postgres", "Не удаётся подключиться к базе PostgreSQL"),
    ("database", "critical", "postgres", "Postgres service refuses all connections"),
    ("database", "critical", "postgres", "Приложение потеряло соединение с SQL базой данных"),
    ("application", "critical", "nginx", "Nginx reverse proxy returns HTTP 502"),
    ("application", "critical", "nginx", "Веб-сервер перестал отвечать на запросы"),
    ("application", "critical", "nginx", "Шлюз приложений возвращает ошибку 503"),
    ("network", "warning", "network", "В сети обнаружена потеря пакетов"),
    ("network", "warning", "network", "Router link is dropping packets"),
    ("network", "warning", "network", "Качество соединения ухудшилось из-за потерь"),
]


def make_runbooks():
    ids = ["cpu", "disk", "postgres", "nginx", "network"]
    runbooks = []
    for rid, (title, condition, category, severity, _steps) in zip(ids, SEEDS):
        runbooks.append(SimpleNamespace(
            id=rid,
            title=title,
            condition_text=condition,
            category=category,
            severity=severity,
            is_active=True,
            embedding=embed(title + " " + condition, kind="passage"),
        ))
    return runbooks


def evaluate_retrieval():
    runbooks = make_runbooks()
    tests = []
    for category, severity, expected_id, text in PROBES:
        classified = {"category": category, "severity": severity}
        alert = {"alert_name": "", "title": text, "description": "", "labels": {}}
        matches = pick_runbooks(alert, classified, runbooks)
        result_ids = [x[0].id for x in matches]
        tests.append({
            "query": text, "category": category, "expected": expected_id,
            "top1": result_ids[0] if result_ids else None,
            "top3": result_ids,
            "correct_top1": bool(result_ids and result_ids[0] == expected_id),
            "correct_top3": expected_id in result_ids,
        })
    n = len(tests)
    return {
        "model": settings.embedding_backend,
        "kind": "handwritten_retrieval_probes_on_five_demo_runbooks",
        "count": n,
        "top1_accuracy": sum(x["correct_top1"] for x in tests) / n,
        "top3_recall": sum(x["correct_top3"] for x in tests) / n,
        "tests": tests,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=("hash", "e5"), default="hash")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    settings.embedding_backend = args.backend
    report = evaluate_retrieval()
    print(f"Backend: {args.backend}; curated probes: {report['count']}")
    print(f"Top-1: {report['top1_accuracy']:.1%}; top-3 recall: {report['top3_recall']:.1%}")
    for case in report["tests"]:
        if not case["correct_top1"]:
            print(f"MISS expected={case['expected']} got={case['top1']} | {case['query']}")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print("Saved:", args.json_out)


if __name__ == "__main__":
    main()
