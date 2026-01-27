from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Protocol

from src.config import AppConfig
from src.http import HttpClient
from src.webapp_db import AdminPanelRow, CheckRow, CmsRow

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AuditContext:
    """
    Контекст одного аудита домена.

    Храним общие зависимости и словарь для обмена данными между модулями.
    """

    domain: str
    session: Any
    http: HttpClient
    config: AppConfig
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CheckUpdate:
    """Результат обновления проверки (таблица domain_checks)."""

    key: str
    row: CheckRow
    description: Optional[str] = None


@dataclass(slots=True)
class AdminPanelUpdate:
    """Результат обновления статуса админ-панели."""

    panel_key: str
    row: AdminPanelRow


@dataclass(slots=True)
class CmsUpdate:
    """Результат обновления CMS для домена."""

    cms_key: str
    cms_name: str
    row: CmsRow


@dataclass(slots=True)
class ModuleResult:
    """
    Результат выполнения модуля.

    additional_modules используется для динамического включения зависимых модулей.
    """

    check_updates: list[CheckUpdate] = field(default_factory=list)
    admin_updates: list[AdminPanelUpdate] = field(default_factory=list)
    cms_updates: list[CmsUpdate] = field(default_factory=list)
    additional_modules: list[str] = field(default_factory=list)


class AuditModule(Protocol):
    """Протокол для подключаемых модулей аудита."""

    key: str
    name: str
    description: str
    depends_on: tuple[str, ...]

    async def run(self, context: AuditContext) -> ModuleResult:
        """Запускает модуль и возвращает результат аудита."""


@dataclass(slots=True)
class ModuleRunSummary:
    """Итог выполнения набора модулей для одного домена."""

    check_updates: list[CheckUpdate] = field(default_factory=list)
    admin_updates: list[AdminPanelUpdate] = field(default_factory=list)
    cms_updates: list[CmsUpdate] = field(default_factory=list)
    executed_modules: list[str] = field(default_factory=list)

    def merge(self, result: ModuleResult, module_key: str) -> None:
        """Добавляет результаты модуля в общий список обновлений."""

        self.check_updates.extend(result.check_updates)
        self.admin_updates.extend(result.admin_updates)
        self.cms_updates.extend(result.cms_updates)
        self.executed_modules.append(module_key)
        logger.debug("Результаты модуля %s добавлены в общий список", module_key)
