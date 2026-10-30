# Changelog

## 1.1.0
- Reverse proxy: Docker DNS dynamic lookup to prevent stale api IP, frontend retries GET on transient outages.
- Error UI: network failures are not shown as empty incident and runbook lists.
- Runbooks: edit in UI, restore archived, safely purge unreferenced archived only.
- Incidents: hide closed in working list without deleting anything.
- AI evaluation: additional 48 hand-authored synthetic examples, separate metrics, clear limitations.
- API contract: restore, purge, hide_closed.
- Data model/DB schema unchanged, preserving existing Docker volumes.

## 1.0.0
- Initial hackathon MVP.
