# Матрица приёмки, тестирования и демо

## Обязательные критерии кейса
| Критерий | Проверка | Артефакт |
|---|---|---|
| Prometheus API | На контролируемом alert rule получен настоящий `firing` через `/api/v1/alerts`, UI отображает импортированный инцидент | screen recording + network/log trace |
| Severity/category/priority >=90% | Frozen независимый тест, таблица confusion matrices, accuracy каждого класса признаков + joint exact match | `reports/ai-evaluation.md`, `tests/fixtures/ai_test.csv` |
| База регламентов | Создать, изменить, архивировать «Если событие X → действие Y» и импортировать CSV | Runbooks UI/DB checks |
| Семантический поиск | Для 10+ размеченных примеров релевантный runbook выводится и указан точный source/version | retrieval test cases |
| Дашборд с рекомендациями | Dashboard, list, Detail, loading/empty/error; рекомендации и основание | E2E browser recording |
| Нет автономных действий | Никаких exec/ssh/systemctl API; кнопки только обновляют checklist+audit; контроль в коде | security review + test |
| `docker compose up --build` | запуск чистого клона, demo sample, README with creds & API example | recorded clean run |

## Автоматические тесты

### Backend pytest
- Контракт: response schema matches OpenAPI, каждый error в problem format, включая 401/403/404/409/422.
- State transition: open→acknowledged→closed; закрытие при firing=409; закрытие с pending checklist=409.
- Дубликаты: 10 одинаковых polling alerts → 1 incident; при новом activeAt → новый incident.
- Ошибка Prometheus 5xx/timeout **не** переводит alert в resolved.
- 2 успеха без alert переводят monitor_state в resolved; 1 отсутствие оставляет firing.
- Retry AI c тем же analysis_id не дублирует recommendations; explicit retry создаёт новую попытку.
- RBAC: operator не может POST/PATCH/DELETE runbook, trigger demo, retry AI.
- Runbook optimistic lock: одинаковая version при двух конкурентных updates → второй 409.
- Невозможность необоснованного runbook_id, отсутствие рекомендаций не вызывает падение.

### Frontend Vitest + MSW
- Все 4 состояния Data fetching (loading/success/empty/error).
- 401 сбрасывает session/показывает login; 409 показывает конфликт и обновляет данные.
- Pagination/filter сохраняется в URL search params.
- UI не показывает «успешно перезапустили сервис»; только «пользователь отметил шаг».

### Playwright E2E
1. login → dashboard → открыть firing incident → увидеть анализ + рекомендации;
2. acknowledge → adopt → отметить шаг done → закрытие не доступно пока alert firing;
3. demo reset → дождаться resolved → close with resolution_note → timeline/audit;
4. missing recommendations → fallback message;
5. simulated AI failure → visible error + retry for admin;
6. runbook add/edit/CSV import + reflected search.

## Целевые технические показатели (внутренние, не критерии кейса)
- На 500 инцидентах GET /incidents p95 <500мс локально без AI-инференса в запросе.
- Доступность UI при падении AI: incident list не пропадает.
- После появления firing на Prometheus — карточка в UI в пределах двух polling-циклов + UI refresh (обычно до ~40сек при 15с sync+10с refresh; не формальный SLA).
- Startup Compose: не использовать искусственных `sleep 60`; healthcheck DB/Redis/Prometheus и retry соединений.

## Оценка качества и ограничения:
Классификатор протестирован на двух воспроизводимых синтетических наборах из 24 и 48 событий. Совместная точность определения категории и критичности составила 91,7% и 95,8% соответственно. Для подтверждения качества на реальных инфраструктурных инцидентах требуется дополнительное тестирование. Демонстрационные сценарии реализованы с использованием Prometheus и генератора тестовых метрик.
