from __future__ import annotations

import json
import logging
import os
from typing import Any, Iterable

import redis
from redis import Redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

# -----------------------------
# Конфигурация и клиент Redis
# -----------------------------

_REDIS_CLIENT: Redis | None = None


def _get_redis_url() -> str:
    """
    Возвращает URL Redis из окружения.

    Используем отдельный helper, чтобы проще логировать и переиспользовать.
    """

    return os.getenv("REDIS_URL", "redis://redis:6379/0")


def get_redis_client() -> Redis | None:
    """
    Ленивая инициализация Redis клиента.

    Если Redis недоступен, возвращаем None, чтобы не ломать основной сценарий.
    """

    global _REDIS_CLIENT
    if _REDIS_CLIENT is not None:
        return _REDIS_CLIENT

    try:
        redis_url = _get_redis_url()
        logger.info("[cache] init redis client: url=%s", redis_url)
        _REDIS_CLIENT = redis.Redis.from_url(redis_url, decode_responses=True)
        # Проверяем доступность соединения, чтобы поймать ошибку сразу.
        _REDIS_CLIENT.ping()
        return _REDIS_CLIENT
    except RedisError as exc:
        logger.error("[cache] redis init failed: %s", exc)
        _REDIS_CLIENT = None
        return None


# -----------------------------
# Ключи кэша
# -----------------------------

def build_report_cache_key(domain: str) -> str:
    """Ключ кэша для отчёта домена."""

    return f"report:{domain.strip().lower()}"


def build_dashboard_cache_key(*, top_n: int, tls_soon_days: int) -> str:
    """Ключ кэша для dashboard (зависит от параметров отображения)."""

    return f"dashboard:top_n={top_n}:tls_soon_days={tls_soon_days}"


def build_domains_focus_cache_key(*, focus: str | None, limit: int, top_n: int, tls_soon_days: int) -> str:
    """Ключ кэша для /domains с фокусом."""

    focus_key = focus or "none"
    return f"domains_focus:focus={focus_key}:limit={limit}:top_n={top_n}:tls_soon_days={tls_soon_days}"


# -----------------------------
# Базовые операции кэша
# -----------------------------

def cache_get_json(key: str) -> dict | None:
    """
    Читает JSON из Redis и возвращает dict.

    Возвращаем None при промахе или ошибке.
    """

    client = get_redis_client()
    if client is None:
        logger.debug("[cache] skip get: redis client unavailable")
        return None

    try:
        raw = client.get(key)
        if not raw:
            logger.debug("[cache] miss: key=%s", key)
            return None
        logger.debug("[cache] hit: key=%s", key)
        return json.loads(raw)
    except (RedisError, json.JSONDecodeError) as exc:
        logger.error("[cache] get failed: key=%s error=%s", key, exc)
        return None


def cache_set_json(key: str, payload: dict) -> bool:
    """
    Записывает JSON в Redis без TTL (бессрочно).
    """

    client = get_redis_client()
    if client is None:
        logger.debug("[cache] skip set: redis client unavailable")
        return False

    try:
        client.set(key, json.dumps(payload, ensure_ascii=False))
        logger.debug("[cache] set: key=%s", key)
        return True
    except RedisError as exc:
        logger.error("[cache] set failed: key=%s error=%s", key, exc)
        return False


def cache_delete(key: str) -> int:
    """
    Удаляет один ключ из Redis и возвращает количество удалённых записей.
    """

    client = get_redis_client()
    if client is None:
        logger.debug("[cache] skip delete: redis client unavailable")
        return 0

    try:
        deleted = client.delete(key)
        logger.debug("[cache] delete: key=%s deleted=%s", key, deleted)
        return int(deleted)
    except RedisError as exc:
        logger.error("[cache] delete failed: key=%s error=%s", key, exc)
        return 0


def cache_delete_by_prefix(prefix: str, *, batch_size: int = 200) -> int:
    """
    Удаляет все ключи по префиксу и возвращает количество удалённых записей.

    Используем SCAN, чтобы не блокировать Redis.
    """

    client = get_redis_client()
    if client is None:
        logger.debug("[cache] skip delete_by_prefix: redis client unavailable")
        return 0

    deleted = 0
    try:
        for chunk in _iter_keys_by_prefix(client, prefix, batch_size=batch_size):
            if not chunk:
                continue
            deleted += int(client.delete(*chunk))
        logger.info("[cache] delete_by_prefix: prefix=%s deleted=%s", prefix, deleted)
        return deleted
    except RedisError as exc:
        logger.error("[cache] delete_by_prefix failed: prefix=%s error=%s", prefix, exc)
        return deleted


def _iter_keys_by_prefix(client: Redis, prefix: str, *, batch_size: int) -> Iterable[list[str]]:
    """
    Итератор по ключам для cache_delete_by_prefix.

    Делим на батчи, чтобы не превышать лимит аргументов DEL.
    """

    buffer: list[str] = []
    for key in client.scan_iter(match=f"{prefix}*"):
        buffer.append(key)
        if len(buffer) >= batch_size:
            yield buffer
            buffer = []
    if buffer:
        yield buffer


# -----------------------------
# Инвалидация доменных кэшей
# -----------------------------

def invalidate_domain_cache(domain: str) -> int:
    """
    Сбрасывает кэши, связанные с конкретным доменом.

    Сейчас удаляем только отчёт, остальные кэши очищаются по префиксу.
    """

    report_key = build_report_cache_key(domain)
    deleted = cache_delete(report_key)
    logger.info("[cache] invalidate domain cache: domain=%s deleted=%s", domain, deleted)
    return deleted


def invalidate_dashboard_cache() -> int:
    """Сбрасывает весь кэш dashboard (все параметры)."""

    return cache_delete_by_prefix("dashboard:")


def invalidate_domains_focus_cache() -> int:
    """Сбрасывает кэш фокусных списков доменов."""

    return cache_delete_by_prefix("domains_focus:")


def invalidate_domains_list_cache() -> int:
    """Сбрасывает кэш списка доменов (если появится в будущем)."""

    return cache_delete_by_prefix("domains_list:")

