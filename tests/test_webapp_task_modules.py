import importlib

import pytest
from types import SimpleNamespace
from contextlib import contextmanager

# Пропускаем тест, если обязательные зависимости Celery/SQLAlchemy недоступны.
pytest.importorskip("celery")
pytest.importorskip("sqlalchemy")


def _load_tasks_module(monkeypatch):
    """
    Загружаем модуль задач с локальной конфигурацией.

    Используем SQLite in-memory, чтобы тесты не зависели от внешней БД.
    """

    # Конфигурируем окружение для безопасного импорта модуля задач.
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("CELERY_ALWAYS_EAGER", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    tasks_module = importlib.import_module("src.webapp_tasks")
    return importlib.reload(tasks_module)


def test_resolve_modules_from_positional_args(monkeypatch):
    """
    Проверяем, что модули читаются из позиционных аргументов.

    Это важно для обратной совместимости со старыми воркерами.
    """

    tasks_module = _load_tasks_module(monkeypatch)

    # Передаём модули через extra_args, имитируя старый формат вызова.
    resolved = tasks_module._resolve_task_modules(None, ("cms", "tls"), {})
    assert resolved == ["cms", "tls"]


def test_resolve_modules_from_kwargs(monkeypatch):
    """
    Проверяем, что модули читаются из kwargs.

    Это позволяет поддерживать разные форматы входных данных из UI.
    """

    tasks_module = _load_tasks_module(monkeypatch)

    resolved = tasks_module._resolve_task_modules(None, (), {"modules": ["cms"]})
    assert resolved == ["cms"]


def test_resolve_modules_from_string(monkeypatch):
    """
    Проверяем обработку одиночной строки в качестве модуля.

    Строка не должна раскладываться на символы.
    """

    tasks_module = _load_tasks_module(monkeypatch)

    resolved = tasks_module._resolve_task_modules("tls", (), {})
    assert resolved == ["tls"]


def test_audit_domain_task_accepts_kwargs(monkeypatch):
    """
    Проверяем, что задача аудита принимает kwargs и корректно прокидывает модули.

    Это защищает от ошибок при обновлении UI, который отправляет параметры по именам.
    """

    tasks_module = _load_tasks_module(monkeypatch)
    captured = {}

    def _fake_audit(domains, _session_factory, module_keys=None):
        """Простейший стаб для контроля входных данных."""

        captured["domains"] = domains
        captured["module_keys"] = module_keys
        return len(domains)

    monkeypatch.setattr(tasks_module, "run_audit_and_persist", _fake_audit)

    result = tasks_module.audit_domain_task(domain="example.com", modules=["availability"])

    assert result == {"processed": 1}
    assert captured["domains"] == ["example.com"]
    assert captured["module_keys"] == ["availability"]


def test_audit_domain_task_accepts_positional(monkeypatch):
    """
    Проверяем, что задача аудита принимает позиционные аргументы.

    Это нужно для совместимости со старыми клиентами/воркерами.
    """

    tasks_module = _load_tasks_module(monkeypatch)
    captured = {}

    def _fake_audit(domains, _session_factory, module_keys=None):
        """Простейший стаб для контроля входных данных."""

        captured["domains"] = domains
        captured["module_keys"] = module_keys
        return len(domains)

    monkeypatch.setattr(tasks_module, "run_audit_and_persist", _fake_audit)

    result = tasks_module.audit_domain_task("example.net", ["tls"])

    assert result == {"processed": 1}
    assert captured["domains"] == ["example.net"]
    assert captured["module_keys"] == ["tls"]


def test_resolve_domain_from_kwargs(monkeypatch):
    """
    Проверяем извлечение домена из kwargs.

    Это важно для режима, когда UI передаёт именованные параметры.
    """

    tasks_module = _load_tasks_module(monkeypatch)

    resolved = tasks_module._resolve_task_domain(None, (), {"domain": "example.org"})
    assert resolved == "example.org"


def test_resolve_modules_from_headers(monkeypatch):
    """
    Проверяем чтение модулей из заголовков задачи.

    Это основной путь передачи модулей из UI, чтобы избежать ошибок сигнатуры.
    """

    tasks_module = _load_tasks_module(monkeypatch)

    resolved = tasks_module._resolve_task_modules(None, (), {}, header_modules=["availability"])
    assert resolved == ["availability"]


def test_audit_domain_task_uses_header_modules(monkeypatch):
    """
    Проверяем, что хелпер корректно читает модули из заголовков Celery.
    """

    tasks_module = _load_tasks_module(monkeypatch)

    request = type(
        "Request",
        (),
        {"headers": {"modules": ["tls"]}},
    )()

    resolved = tasks_module._get_header_modules(request)
    assert resolved == ["tls"]


def test_resolve_limit_from_positional(monkeypatch):
    """
    Проверяем извлечение лимита из позиционного аргумента.

    Это важно для обратной совместимости, когда UI передаёт limit первым параметром.
    """

    tasks_module = _load_tasks_module(monkeypatch)

    resolved_limit, remaining = tasks_module._resolve_task_limit(None, (25, "tls"), {})
    assert resolved_limit == 25
    assert remaining == ("tls",)


def test_resolve_limit_from_kwargs(monkeypatch):
    """
    Проверяем извлечение лимита из kwargs.

    Полезно при вызовах с именованными аргументами.
    """

    tasks_module = _load_tasks_module(monkeypatch)

    resolved_limit, remaining = tasks_module._resolve_task_limit(None, (), {"limit": 10})
    assert resolved_limit == 10
    assert remaining == ()


def test_audit_all_task_accepts_modules(monkeypatch):
    """
    Проверяем, что audit_all_task принимает модули и корректно их передаёт.
    """

    tasks_module = _load_tasks_module(monkeypatch)
    captured = {}

    # Подменяем вызов аудита, чтобы зафиксировать входные параметры.
    def _fake_audit(domains, _session_factory, module_keys=None):
        captured["domains"] = domains
        captured["module_keys"] = module_keys
        return len(domains)

    @contextmanager
    def _fake_session_factory():
        # Контекстный менеджер, имитирующий работу с БД без реального подключения.
        yield None

    # Подменяем зависимости на безопасные заглушки.
    monkeypatch.setattr(tasks_module, "run_audit_and_persist", _fake_audit)
    monkeypatch.setattr(tasks_module, "list_domains", lambda _session, limit: [SimpleNamespace(domain="a")])
    # Подменяем объект состояния БД целиком, так как оригинальный dataclass заморожен.
    monkeypatch.setattr(tasks_module, "db_state", SimpleNamespace(session_factory=_fake_session_factory))

    result = tasks_module.audit_all_task(modules=["availability"])

    assert result == {"processed": 1}
    assert captured["domains"] == ["a"]
    assert captured["module_keys"] == ["availability"]


def test_audit_limit_task_accepts_positional(monkeypatch):
    """
    Проверяем, что audit_limit_task корректно принимает позиционные аргументы.
    """

    tasks_module = _load_tasks_module(monkeypatch)
    captured = {}

    def _fake_audit(domains, _session_factory, module_keys=None):
        # Фиксируем входные данные для последующих проверок.
        captured["domains"] = domains
        captured["module_keys"] = module_keys
        return len(domains)

    @contextmanager
    def _fake_session_factory():
        # Имитируем контекст БД, чтобы не требовать внешних зависимостей.
        yield None

    monkeypatch.setattr(tasks_module, "run_audit_and_persist", _fake_audit)
    monkeypatch.setattr(tasks_module, "list_domains", lambda _session, limit: [SimpleNamespace(domain="b")])
    # Подменяем объект состояния БД целиком, так как оригинальный dataclass заморожен.
    monkeypatch.setattr(tasks_module, "db_state", SimpleNamespace(session_factory=_fake_session_factory))

    result = tasks_module.audit_limit_task(3, ["tls"])

    assert result == {"processed": 1}
    assert captured["domains"] == ["b"]
    assert captured["module_keys"] == ["tls"]
