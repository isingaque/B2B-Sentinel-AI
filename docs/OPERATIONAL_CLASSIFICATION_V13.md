# Sentinel AI v1.3 — source-aware classification and quality measurement

**Status:** experimental branch `classifier-operational-v13`; stable `main` is not modified. No paid external AI API.

## Scope

The classifier continues to use local, interpretable heuristics. It now considers Prometheus monitoring source labels (especially `job`, `exporter`, `service`) before interpreting an ambiguous alert name. For recognized exporters, this improves incident category classification. The source-provided `severity` label is used directly when available and the backend derives priority from it. If a label is missing, a heuristic estimates severity and flags the result for manual review.

Importantly, this **is not a new neural model** and the source metadata route is not independent ML prediction. The UI intentionally does not display an invented statistical confidence percentage.

## Three evaluation modes

The reproducible benchmark uses **158 published Prometheus alert rules from 13 exporter configurations** in `backend/tests/fixtures/heldout_prometheus_rules.csv`. These are public alert definitions, **not observed production incidents**. The reference category is assigned according to exporter family and may be debatable for mixed-purpose services. The reference severity is taken from the published alert rule.

The data has already been inspected during the development of earlier classifiers, so the results must **not** be described as a previously unseen, independent external test.

| Input to v1.3 | Category accuracy | Severity accuracy | Priority accuracy | Joint accuracy |
| --- | ---: | ---: | ---: | ---: |
| Alert name only (`--mode blind`) | 77.2% | 60.8% | 60.8% | **46.8%** |
| Alert name + proxy `job` (`--mode source`) | 100% | 60.8% | 60.8% | **60.8%** |
| Alert name + proxy `job` + configured `severity` (`--mode operational`) | 100% | 100% | 100% | **100%** |

**How the source job is constructed in this test:** the `job` string is approximated from the public configuration's exporter directory and file names, not captured from a running Prometheus installation. Since the ground-truth category also derives from the exporter family, **100% category agreement is a mapping/normalization check, not a proof of generalizable prediction accuracy**. In the last row, severity is the exact configured label from the reference rule, so it is a **passthrough/normalization test, not AI severity inference**. Priority is a deterministic mapping from severity, so not a separately learned target.

This test demonstrates correct full-event **processing under favorable metadata conditions**, not compliance with an independently predicted `>=90%` industrial-incident accuracy requirement.

## How the actual product uses metadata

- If `labels.category` contains a valid category, the system takes that source label.
- Otherwise the classifier attempts to identify the category from known `job`/`exporter`/`service` metadata.
- If the job is unknown, it attempts identification from the alert name and description, with no guarantee.
- If `labels.severity` is one of `critical`, `warning`, `info`, it is used as defined by the monitoring system.
- Otherwise the classifier attempts a heuristic estimate, explicitly marked as needing manual review.
- The API and UI retain the same incident lifecycle, proposed runbooks and human-only checklists.

Neither neural inference nor autonomous commands have been introduced.

## Verified checks

GitHub Actions checks Python tests, Frontend build and the following public rule diagnostics:

```bash
cd backend
PYTHONPATH=. python ../scripts/evaluate_public_rules.py --engine v2 --dataset tests/fixtures/heldout_prometheus_rules.csv --mode blind
PYTHONPATH=. python ../scripts/evaluate_public_rules.py --engine v2 --dataset tests/fixtures/heldout_prometheus_rules.csv --mode source
PYTHONPATH=. python ../scripts/evaluate_public_rules.py --engine v2 --dataset tests/fixtures/heldout_prometheus_rules.csv --mode operational
```

For a local Docker test, download the ZIP of this **separate branch**, unpack to a new directory, and prepare `.env`:

```dotenv
CLASSIFIER_ENGINE=v2
FRONTEND_PORT=8082
PROMETHEUS_PORT=9092
```

Then in PowerShell:

```powershell
docker compose -p sentinel_ai_operational_v13 up --build -d
docker compose -p sentinel_ai_operational_v13 ps
docker compose -p sentinel_ai_operational_v13 cp .\backend\tests api:/srv/tests
docker compose -p sentinel_ai_operational_v13 cp .\scripts\evaluate_public_rules.py api:/srv/evaluate_public_rules.py
docker compose -p sentinel_ai_operational_v13 exec api python /srv/evaluate_public_rules.py --engine v2 --mode operational --dataset /srv/tests/fixtures/heldout_prometheus_rules.csv
```

A **fresh clean environment and complete Docker Smoke Test** still need to be verified on the user's machine. Stable v1.1 remains unchanged.

## What is still needed for the specification's 90% threshold

1. Confirm whether the requirement concerns **independent inference** or the **whole monitoring-based incident workflow**, in which source severity labels may legitimately be authoritative.
2. For independent inference, obtain a never-used evaluation set of actual alert events with complete title/description/metric thresholds and separately assigned expert labels, excluding direct category/severity hints.
3. Develop and evaluate an improved learned classifier if rule-based inference remains below 90%.
4. If operational source-aware processing is accepted, demonstrate that each monitoring integration actually emits the promised `job` and `severity` metadata and measure on these raw events.

**No claim of independently measured >=90% real-world AI accuracy is made here.**
