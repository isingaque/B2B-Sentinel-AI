"""Idempotent first-run seed; local demo accounts, procedures, pgvector extension."""
from sqlalchemy import text, select
from app.database import engine, Base, SessionLocal
from app.models import User, MonitoringSource, Runbook, RunbookStep
from app.auth import hasher
from app.ai import embed
from app.config import settings
from app import models  # register all ORM models

SEEDS = [
 ("Высокая загрузка процессора", "HighCPUUsage CPU load processor utilization сервер процессор нагрузка 95%", "server", "critical", [
 "Проверить метрики CPU, время начала нагрузки и затронутый сервер.", "Просмотреть список процессов и определить источник нагрузки без завершения процессов.", "Согласовать вмешательство с ответственным инженером; при необходимости вручную ограничить ресурсы виновного процесса.", "Убедиться, что график CPU нормализовался, и записать результат." ]),
 ("Недостаточно свободного места", "LowDiskSpace disk full filesystem free space /var logs сервер диск место", "server", "warning", [
 "Проверить свободное место через df -h и определить затронутую файловую систему.", "Найти каталоги с самым большим использованием, проверить лог-ротацию.", "Перед удалением файлов подтвердить у владельца сервиса допустимый способ очистки.", "Вручную выполнить согласованную очистку и проверить метрики диска." ]),
 ("PostgreSQL недоступен", "PostgreSQLDown postgres database connection refused db down postgres БД недоступна", "database", "critical", [
 "Проверить доступность хоста базы данных и состояние PostgreSQL.", "Посмотреть системный журнал PostgreSQL и причину отказа без внесения изменений.", "Оповестить ответственного за БД и согласовать план восстановления или ручного рестарта.", "После действий инженера проверить подключение приложения к БД и алерты." ]),
 ("Неработоспособность Nginx", "NginxDown nginx HTTP 502 503 service unavailable application reverse proxy", "application", "critical", [
 "Проверить HTTP-ответ, доступность upstream и состояние Nginx.", "Просмотреть журнал ошибок Nginx и доступность upstream-сервисов.", "Согласовать с ответственным инженером ручной перезапуск только при подтверждённой необходимости.", "Повторить HTTP-запрос и убедиться, что предупреждение исчезло." ]),
 ("Потеря пакетов в сети", "NetworkPacketLoss packet loss network interface high latency router link сеть потеря пакетов", "network", "warning", [
 "Проверить метрики потерь пакетов, интерфейс и масштабы проблемы.", "Провести согласованные диагностики ping/traceroute и проверить состояние линка.", "Перед изменением маршрутизации эскалировать инцидент сетевому инженеру.", "Убедиться в восстановлении качества связи и зафиксировать результат." ]),
]

def bootstrap():
    with engine.begin() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    Base.metadata.create_all(engine)
    # Track vector encoding to avoid comparing incompatible E5 / hash vectors.
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS runbook_embedding_state "
            "(id INTEGER PRIMARY KEY, backend TEXT NOT NULL)"
        ))
    with SessionLocal() as db:
        if not db.scalar(select(MonitoringSource).where(MonitoringSource.name == "Prometheus")):
            db.add(MonitoringSource(name="Prometheus", kind="prometheus", health="never_connected", enabled=True))
        for username, role in (("admin", "admin"), ("operator", "operator")):
            if not db.scalar(select(User).where(User.username == username)):
                db.add(User(username=username, role=role, password_hash=hasher.hash(settings.demo_password)))
        for title, condition, category, severity, steps in SEEDS:
            if db.scalar(select(Runbook).where(Runbook.title == title)):
                continue
            r = Runbook(title=title, condition_text=condition, category=category,
                        severity=severity, embedding=embed(title + " " + condition))
            r.steps = [RunbookStep(position=i+1, instruction=s, is_risky=i == 2) for i,s in enumerate(steps)]
            db.add(r)
        configured = db.execute(text(
            "SELECT backend FROM runbook_embedding_state WHERE id = 1"
        )).scalar_one_or_none()
        if configured != settings.embedding_backend:
            # Reindex once on first deploy or when the configured backend changes.
            # Background workers start after the API bootstrap completes.
            for book in db.scalars(select(Runbook)).all():
                book.embedding = embed(
                    f"{book.title} {book.condition_text}", kind="passage"
                )
            db.execute(text(
                "INSERT INTO runbook_embedding_state (id, backend) VALUES (1, :backend) "
                "ON CONFLICT (id) DO UPDATE SET backend = EXCLUDED.backend"
            ), {"backend": settings.embedding_backend})
        db.commit()

if __name__ == "__main__":
    bootstrap()
