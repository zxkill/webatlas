from __future__ import annotations

import logging
from typing import Any, Iterable, Optional

from celery import Celery

from src.webapp_audit import run_audit_and_persist
from src.webapp_config import load_webapp_config
from src.webapp_db import (
    create_db_state,
    create_domain,
    import_domains_from_file,
    init_db,
    list_domains,
)
from src.webapp_logging import configure_logging

logger = logging.getLogger(__name__)

configure_logging()

config = load_webapp_config()

db_state = create_db_state(config.database_url)
init_db(db_state)

celery_app = Celery(
    "webatlas",
    broker=config.celery_broker_url,
    backend=config.celery_backend_url,
)
celery_app.conf.task_always_eager = config.celery_always_eager
celery_app.conf.task_eager_propagates = True


def _normalize_modules(modules: Optional[Iterable[str]] | str) -> list[str] | None:
    """
    Преобразует список модулей в удобный для логов формат.

    Мы отдельно обрабатываем строку, чтобы не развалить её на символы при list().
    """

    if modules is None:
        logger.debug("Список модулей не передан, вернём None")
        return None
    if isinstance(modules, str):
        logger.debug("Список модулей передан строкой, оборачиваем в список: %s", modules)
        return [modules]
    normalized_modules = list(modules)
    logger.debug("Нормализован список модулей: %s", normalized_modules)
    return normalized_modules


def _resolve_task_modules(
    modules: Optional[Iterable[str]] | str,
    extra_args: tuple[Any, ...],
    extra_kwargs: dict[str, Any],
    header_modules: Optional[Iterable[str]] | str = None,
) -> list[str] | None:
    """
    Извлекает список модулей из аргументов Celery-задачи.

    Этот хелпер нужен для обратной совместимости, когда UI отправляет дополнительные
    аргументы, а воркер ещё запущен со старой сигнатурой.
    """

    # Сохраняем исходное значение, чтобы использовать его как приоритетное.
    resolved_modules: Optional[Iterable[str]] | str | None = modules

    # Если модули не заданы явно, пробуем извлечь их из позиционных аргументов.
    consumed_all_positional = False
    if resolved_modules is None and extra_args:
        # Если пришло несколько позиционных аргументов, считаем, что это список модулей.
        if len(extra_args) > 1 and all(isinstance(item, str) for item in extra_args):
            resolved_modules = list(extra_args)
            consumed_all_positional = True
        else:
            resolved_modules = extra_args[0]
        logger.warning("Модули переданы позиционно, применяем обратную совместимость: %s", resolved_modules)

    # Если нет позиционных аргументов, проверяем kwargs.
    if resolved_modules is None and "modules" in extra_kwargs:
        resolved_modules = extra_kwargs.get("modules")
        logger.warning("Модули переданы через kwargs, применяем обратную совместимость: %s", resolved_modules)

    # Если модули всё ещё не заданы, используем заголовки задачи (актуально для UI).
    if resolved_modules is None and header_modules is not None:
        resolved_modules = header_modules
        logger.info("Модули получены из заголовков задачи: %s", resolved_modules)

    # Логируем лишние аргументы, чтобы упростить диагностику.
    unexpected_args = () if consumed_all_positional else extra_args[1:]
    unexpected_kwargs = {
        key: value
        for key, value in extra_kwargs.items()
        if key not in {"modules", "domain"}
    }
    if unexpected_args or unexpected_kwargs:
        logger.warning(
            "Обнаружены лишние аргументы audit_domain_task: args=%s kwargs=%s",
            unexpected_args,
            unexpected_kwargs,
        )

    return _normalize_modules(resolved_modules)


def _resolve_task_domain(
    domain: Optional[str],
    extra_args: tuple[Any, ...],
    extra_kwargs: dict[str, Any],
) -> str:
    """
    Разбирает домен из набора аргументов Celery-задачи.

    Нам важно поддерживать разные схемы передачи (позиционные, kwargs),
    чтобы UI и воркеры могли обновляться независимо.
    """

    resolved_domain = domain

    if resolved_domain is None and extra_args:
        resolved_domain = extra_args[0]
        logger.warning("Домен передан позиционно, применяем обратную совместимость: %s", resolved_domain)

    if resolved_domain is None and "domain" in extra_kwargs:
        resolved_domain = extra_kwargs.get("domain")
        logger.warning("Домен передан через kwargs, применяем обратную совместимость: %s", resolved_domain)

    if not resolved_domain:
        logger.error(
            "Не удалось извлечь домен для аудита: args=%s kwargs_keys=%s",
            list(extra_args),
            list(extra_kwargs.keys()),
        )
        raise ValueError("Не задан домен для аудита")

    if not isinstance(resolved_domain, str):
        logger.error("Домен должен быть строкой, получено: %s", type(resolved_domain))
        raise TypeError("Домен должен быть строкой")

    return resolved_domain


def _get_header_modules(request: Any) -> Optional[Iterable[str]] | str:
    """
    Достаёт модули из заголовков Celery-задачи.

    Храним эту логику отдельно, чтобы проще тестировать и безопасно обрабатывать None.
    """

    if request is None:
        logger.debug("Запрос Celery отсутствует, заголовки недоступны")
        return None

    headers = getattr(request, "headers", None)
    if not isinstance(headers, dict):
        logger.debug("Заголовки Celery отсутствуют или имеют неожиданный формат: %s", type(headers))
        return None

    return headers.get("modules")


@celery_app.task(name="webatlas.add_domain")
def add_domain_task(domain: str, source: str = "manual") -> dict[str, str]:
    """
    Фоновая задача для добавления домена в базу.

    Возвращаем словарь, чтобы удобно отслеживать результат в логах и UI.
    """

    logger.info("Получена задача на добавление домена: %s", domain)
    with db_state.session_factory() as session:
        record = create_domain(session, domain=domain, source=source)
    return {"domain": record.domain, "source": record.source}


@celery_app.task(name="webatlas.import_domains_from_file")
def import_domains_from_file_task(file_path: str) -> dict[str, int]:
    """Импортируем домены из файла по запросу админки."""

    logger.info("Получена задача на импорт доменов из файла: %s", file_path)
    with db_state.session_factory() as session:
        stats = import_domains_from_file(session, file_path, source="file")
    return {
        "total_lines": stats.total_lines,
        "normalized_domains": stats.normalized_domains,
        "unique_domains": stats.unique_domains,
        "inserted_domains": stats.inserted_domains,
        "skipped_duplicates": stats.skipped_duplicates,
    }


@celery_app.task(name="webatlas.audit_all")
def audit_all_task(modules: Optional[Iterable[str]] = None) -> dict[str, int]:
    """Запускаем аудит всех доменов из базы."""

    normalized_modules = _normalize_modules(modules)
    logger.info("Получена задача на аудит всех доменов (модули=%s)", normalized_modules)
    with db_state.session_factory() as session:
        domains = [record.domain for record in list_domains(session, limit=1000000)]
    processed = run_audit_and_persist(domains, db_state.session_factory, module_keys=normalized_modules)
    return {"processed": processed}


@celery_app.task(name="webatlas.audit_limit")
def audit_limit_task(limit: int, modules: Optional[Iterable[str]] = None) -> dict[str, int]:
    """Запускаем аудит ограниченного числа доменов."""

    normalized_modules = _normalize_modules(modules)
    logger.info("Получена задача на аудит доменов с лимитом: %s (модули=%s)", limit, normalized_modules)
    with db_state.session_factory() as session:
        domains = [record.domain for record in list_domains(session, limit=limit)]
    processed = run_audit_and_persist(domains, db_state.session_factory, module_keys=normalized_modules)
    return {"processed": processed}


@celery_app.task(name="webatlas.audit_domain", bind=True)
def audit_domain_task(self, *task_args: Any, **task_kwargs: Any) -> dict[str, int]:
    """
    Запускаем аудит конкретного домена.

    Принимаем extra_args/extra_kwargs для защиты от несовпадения сигнатур между UI и воркерами.
    """

    # Разбираем домен и модули из любого допустимого набора аргументов.
    # Это защищает от несовпадения сигнатур между версиями UI и воркеров.
    domain = _resolve_task_domain(
        task_kwargs.get("domain"),
        task_args,
        task_kwargs,
    )
    # Извлекаем модули из заголовков запроса, если UI передал их таким способом.
    header_modules = _get_header_modules(getattr(self, "request", None))
    normalized_modules = _resolve_task_modules(
        task_kwargs.get("modules"),
        task_args[1:],
        task_kwargs,
        header_modules=header_modules,
    )
    logger.info(
        "Получена задача на аудит домена: %s (модули=%s, extra_args=%s, extra_kwargs_keys=%s)",
        domain,
        normalized_modules,
        list(task_args),
        list(task_kwargs.keys()),
    )
    processed = run_audit_and_persist([domain], db_state.session_factory, module_keys=normalized_modules)
    return {"processed": processed}
