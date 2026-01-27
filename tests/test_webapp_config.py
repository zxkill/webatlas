import importlib
import os

# Подробно описываем, что в тесте проверяются дефолты и явные переменные окружения.

def test_webapp_config_defaults(monkeypatch):
    # Очищаем окружение, чтобы проверить дефолтные значения конфигурации.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    monkeypatch.delenv("CELERY_BACKEND_URL", raising=False)
    monkeypatch.delenv("APP_HOST", raising=False)
    monkeypatch.delenv("APP_PORT", raising=False)
    monkeypatch.delenv("CELERY_ALWAYS_EAGER", raising=False)

    config_module = importlib.import_module("src.webapp_config")
    config = config_module.load_webapp_config()

    assert config.database_url.startswith("postgresql")
    assert config.redis_url.startswith("redis")
    assert config.app_port == 8088
    assert config.celery_always_eager is False


# Проверяем, что при наличии переменных окружения параметры корректно подхватываются.

def test_webapp_config_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///test.db")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/9")
    monkeypatch.setenv("CELERY_BROKER_URL", "redis://localhost:6379/7")
    monkeypatch.setenv("CELERY_BACKEND_URL", "redis://localhost:6379/8")
    monkeypatch.setenv("APP_HOST", "127.0.0.1")
    monkeypatch.setenv("APP_PORT", "9090")
    monkeypatch.setenv("CELERY_ALWAYS_EAGER", "true")

    config_module = importlib.import_module("src.webapp_config")
    config = config_module.load_webapp_config()

    assert config.database_url == "sqlite:///test.db"
    assert config.redis_url == "redis://localhost:6379/9"
    assert config.celery_broker_url == "redis://localhost:6379/7"
    assert config.celery_backend_url == "redis://localhost:6379/8"
    assert config.app_host == "127.0.0.1"
    assert config.app_port == 9090
    assert config.celery_always_eager is True
