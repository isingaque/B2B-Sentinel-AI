# Организация команды и точки расширения

- **Backend Core:** `backend/app/main.py`, `models.py`, `schemas.py`, `serialization.py`, `auth.py`. Любые схемы сначала меняются в `contracts/openapi.yaml`.
- **Backend Integrations:** `backend/app/tasks.py`, `services.py`, `exporter/`, `prometheus/`, Docker Compose. Внешние события нормализуются в `normalize_alert()`; при ошибке API НЕ переводить сигналы в resolved.
- **AI:** `backend/app/ai.py`, `backend/tests/test_ai.py`, `scripts/evaluate_ai.py`. API подбора: `classify(alert:dict) -> dict` и `pick_runbooks(alert, classified, runbooks) -> list[(Runbook,score,reason)]`.
- **Frontend Dashboard:** `frontend/src/App.tsx` — overview, incidents, header/sidebar. Изменять DTO только через OpenAPI и `frontend/src/api.ts`.
- **Frontend Workflows & QA:** runbooks, checklist, simulator, analytics, frontend UI acceptance, `scripts/smoke_test.py`.

Главные инварианты: сервер — единственный писатель бизнес-сущностей, AI не выполняет команд; `monitor_state` задаётся Prometheus, `workflow_status` — человеком; `recommendation.steps_snapshot` остаётся неизменяемым даже после редактирования регламента. Любое изменение публичного API требует корректировки `contracts/openapi.yaml`, примеров и тестов в одном PR.

Для настоящего промышленного выпуска потребуется Alembic, независимый обучающий/валидационный датасет AI, полноценная аутентификация и инфраструктурная защита. Эти расширения **не подменяют** функциональность MVP.
