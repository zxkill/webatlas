import importlib
import os

import pytest

# Пропускаем тест, если обязательные зависимости Celery/SQLAlchemy недоступны.
pytest.importorskip("celery")
pytest.importorskip("sqlalchemy")

from src.webapp_db import Domain


# Проверяем, что Celery-задача добавляет домен даже в режиме eager.

def test_webapp_task_add_domain(monkeypatch):
    dsn = os.getenv("POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("POSTGRES_TEST_DSN не задан, пропускаем интеграционный тест")

    monkeypatch.setenv("DATABASE_URL", dsn)
    monkeypatch.setenv("CELERY_ALWAYS_EAGER", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    tasks_module = importlib.import_module("src.webapp_tasks")
    tasks_module = importlib.reload(tasks_module)

    with tasks_module.db_state.session_factory() as session:
        session.query(Domain).delete()
        session.commit()

    result = tasks_module.add_domain_task.delay("test.local", source="task")
    payload = result.get()

    assert payload["domain"] == "test.local"
    assert payload["source"] == "task"

    with tasks_module.db_state.session_factory() as session:
        domains = session.query(Domain).all()
    assert len(domains) == 1
