import pytest

import src.cache as cache
from src.webapp_db import get_dashboard_data, get_domains_focus_data


class DummyRedis:
    """Минимальный in-memory Redis для unit-тестов кэша."""

    def __init__(self) -> None:
        self.storage: dict[str, str] = {}

    def ping(self) -> bool:
        return True

    def get(self, key: str) -> str | None:
        return self.storage.get(key)

    def set(self, key: str, value: str) -> bool:
        self.storage[key] = value
        return True

    def delete(self, *keys: str) -> int:
        deleted = 0
        for key in keys:
            if key in self.storage:
                del self.storage[key]
                deleted += 1
        return deleted

    def scan_iter(self, match: str):
        prefix = match.rstrip("*")
        for key in list(self.storage.keys()):
            if key.startswith(prefix):
                yield key


def test_cache_set_get_delete_roundtrip(monkeypatch):
    # Подменяем Redis клиент на in-memory вариант.
    dummy = DummyRedis()
    monkeypatch.setattr(cache, "get_redis_client", lambda: dummy)

    payload = {"status": "ok", "items": [1, 2, 3]}
    key = "unit:test"

    assert cache.cache_get_json(key) is None
    assert cache.cache_set_json(key, payload) is True
    assert cache.cache_get_json(key) == payload
    assert cache.cache_delete(key) == 1
    assert cache.cache_get_json(key) is None


def test_cache_delete_by_prefix(monkeypatch):
    # Проверяем удаление по префиксу, чтобы инвалидация была безопасной.
    dummy = DummyRedis()
    monkeypatch.setattr(cache, "get_redis_client", lambda: dummy)

    cache.cache_set_json("dash:a", {"x": 1})
    cache.cache_set_json("dash:b", {"x": 2})
    cache.cache_set_json("report:c", {"x": 3})

    deleted = cache.cache_delete_by_prefix("dash:")
    assert deleted == 2
    assert cache.cache_get_json("report:c") == {"x": 3}


def test_cached_dashboard_payload_short_circuit(monkeypatch):
    # Проверяем, что при наличии кэша функция не трогает БД.
    cached = {"kpis": {"total_domains": 1}}
    monkeypatch.setattr("src.webapp_db.cache_get_json", lambda key: cached)

    result = get_dashboard_data(None, top_n=5, tls_soon_days=14)
    assert result == cached


def test_cached_focus_payload_short_circuit(monkeypatch):
    # Проверяем, что фокусные данные возвращаются из кэша без запросов БД.
    cached = {"domains": [], "focus": {"key": "critical", "count": 0, "items": []}}
    monkeypatch.setattr("src.webapp_db.cache_get_json", lambda key: cached)

    result = get_domains_focus_data(None, focus="critical", limit=10, top_n=5, tls_soon_days=14)
    assert result == cached
