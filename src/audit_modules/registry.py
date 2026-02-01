from __future__ import annotations

import logging
from collections.abc import Iterable

from src.audit_modules.availability.availability import AvailabilityModule
from src.audit_modules.admin_detect.admin_detect import AdminDetectModule
from src.audit_modules.cms_detect.module import CmsDetectModule
from src.audit_modules.tls_certificate.tls_certificate import TlsCertificateModule
from src.audit_modules.types import AuditModule

logger = logging.getLogger(__name__)


MODULES: list[AuditModule] = [
    AvailabilityModule(),
    TlsCertificateModule(),
    CmsDetectModule(),
    AdminDetectModule(),
]


def list_modules() -> list[AuditModule]:
    """Возвращает список всех доступных модулей в фиксированном порядке."""

    return list(MODULES)


def get_registry() -> dict[str, AuditModule]:
    """Строит словарь key -> модуль для быстрого доступа."""

    return {module.key: module for module in MODULES}


def resolve_module_plan(selected_keys: Iterable[str] | None) -> list[str]:
    """
    Формирует финальный список модулей с учётом зависимостей.

    Если selected_keys не передан, считаем что выбраны все модули.
    """

    registry = get_registry()
    if selected_keys is None:
        logger.info("Модули не указаны, запускаем все доступные")
        return [module.key for module in MODULES]

    resolved: set[str] = set()

    def _add_with_deps(key: str) -> None:
        module = registry.get(key)
        if module is None:
            logger.warning("Модуль %s не найден и будет пропущен", key)
            return
        for dep in module.depends_on:
            _add_with_deps(dep)
        resolved.add(key)

    for key in selected_keys:
        _add_with_deps(key)

    ordered = [module.key for module in MODULES if module.key in resolved]
    logger.info("Итоговый список модулей: %s", ordered)
    return ordered
