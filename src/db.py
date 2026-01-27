from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from src.webapp_db import (
    AdminPanel,
    AdminPanelRow,
    Check,
    CheckRow,
    Cms,
    Domain,
    DomainCheck,
    DomainCms,
    create_db_state,
    init_db,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CmsRow:
    """Результат определения CMS для домена в формате, удобном для записи."""

    status: str
    confidence: int
    evidence_json: str


class Database:
    """
    Обёртка над PostgreSQL через SQLAlchemy: схема, upsert доменов,
    обновление результатов аудита и вспомогательные методы.
    """

    def __init__(self, url: str) -> None:
        # Инициализируем движок и схему PostgreSQL.
        self._state = create_db_state(url)
        init_db(self._state)
        self._session: Session = self._state.session_factory()
        logger.info("Подключение к базе данных успешно создано")

    def close(self) -> None:
        # Закрываем сессию и освобождаем ресурсы подключения.
        self._session.close()
        self._state.engine.dispose()
        logger.info("Подключение к базе данных закрыто")

    def commit(self) -> None:
        # Явно фиксируем изменения, чтобы транзакция была предсказуемой.
        self._session.commit()

    def upsert_domain(self, domain: str, source: str = "manual") -> None:
        """
        Добавляет домен в БД или обновляет метаданные, если он уже есть.
        """

        normalized = domain.strip().lower()
        logger.debug("Upsert домена: raw=%s normalized=%s", domain, normalized)
        record = self._session.query(Domain).filter(Domain.domain == normalized).one_or_none()
        if record:
            record.source = source
            record.updated_at = func.now()
            logger.info("Домен обновлён: %s", normalized)
        else:
            self._session.add(Domain(domain=normalized, source=source))
            logger.info("Домен добавлен: %s", normalized)

    def _get_domain_id(self, domain: str) -> Optional[int]:
        # Получаем id домена — ключ для всех связанных таблиц.
        record = self._session.query(Domain).filter(Domain.domain == domain).one_or_none()
        return record.id if record else None

    def _ensure_check(self, key: str, description: str | None = None) -> int:
        """
        Регистрирует тип проверки (например, bitrix) и возвращает её id.
        """

        record = self._session.query(Check).filter(Check.key == key).one_or_none()
        if record:
            if description and record.description != description:
                record.description = description
            return record.id

        record = Check(key=key, description=description)
        self._session.add(record)
        self._session.flush()
        return record.id

    def _ensure_cms(self, key: str, name: str) -> int:
        """
        Регистрирует CMS и возвращает её id.
        """

        record = self._session.query(Cms).filter(Cms.key == key).one_or_none()
        if record:
            if record.name != name:
                record.name = name
            return record.id

        record = Cms(key=key, name=name)
        self._session.add(record)
        self._session.flush()
        return record.id

    def update_check(self, domain: str, check_key: str, row: CheckRow, description: str | None = None) -> None:
        """
        Обновляет результаты конкретной проверки (например, bitrix).
        """

        domain_id = self._get_domain_id(domain)
        if domain_id is None:
            logger.warning("Домен не найден при обновлении проверки: %s", domain)
            return

        check_id = self._ensure_check(check_key, description)
        record = (
            self._session.query(DomainCheck)
            .filter(DomainCheck.domain_id == domain_id, DomainCheck.check_id == check_id)
            .one_or_none()
        )
        timestamp = int(time.time())
        if record:
            record.status = row.status
            record.score = row.score
            record.evidence_json = row.evidence_json
            record.last_checked_ts = timestamp
        else:
            self._session.add(
                DomainCheck(
                    domain_id=domain_id,
                    check_id=check_id,
                    status=row.status,
                    score=row.score,
                    evidence_json=row.evidence_json,
                    last_checked_ts=timestamp,
                )
            )
        logger.info("Обновлены результаты проверки %s для домена %s", check_key, domain)

    def update_admin_panel(self, domain: str, panel_key: str, row: AdminPanelRow) -> None:
        """
        Обновляет статус доступности админки (для разных CMS/фреймворков).
        """

        domain_id = self._get_domain_id(domain)
        if domain_id is None:
            logger.warning("Домен не найден при обновлении админки: %s", domain)
            return

        record = (
            self._session.query(AdminPanel)
            .filter(AdminPanel.domain_id == domain_id, AdminPanel.panel_key == panel_key)
            .one_or_none()
        )
        timestamp = int(time.time())
        if record:
            record.status = row.status
            record.http_status = row.http_status
            record.final_url = row.final_url
            record.evidence_json = row.evidence_json
            record.last_checked_ts = timestamp
        else:
            self._session.add(
                AdminPanel(
                    domain_id=domain_id,
                    panel_key=panel_key,
                    status=row.status,
                    http_status=row.http_status,
                    final_url=row.final_url,
                    evidence_json=row.evidence_json,
                    last_checked_ts=timestamp,
                )
            )
        logger.info("Обновлён статус админки %s для домена %s", panel_key, domain)

    def update_domain_cms(
        self,
        domain: str,
        cms_key: str,
        cms_name: str,
        status: str,
        confidence: int,
        evidence_json: str,
    ) -> None:
        """
        Фиксирует принадлежность домена к CMS (например, bitrix).
        """

        domain_id = self._get_domain_id(domain)
        if domain_id is None:
            logger.warning("Домен не найден при обновлении CMS: %s", domain)
            return

        cms_id = self._ensure_cms(cms_key, cms_name)
        record = (
            self._session.query(DomainCms)
            .filter(DomainCms.domain_id == domain_id, DomainCms.cms_id == cms_id)
            .one_or_none()
        )
        timestamp = int(time.time())
        if record:
            record.status = status
            record.confidence = confidence
            record.evidence_json = evidence_json
            record.last_checked_ts = timestamp
        else:
            self._session.add(
                DomainCms(
                    domain_id=domain_id,
                    cms_id=cms_id,
                    status=status,
                    confidence=confidence,
                    evidence_json=evidence_json,
                    last_checked_ts=timestamp,
                )
            )
        logger.info("Обновлены данные CMS %s для домена %s", cms_key, domain)

    def load_domains(self, limit: int | None = None) -> list[str]:
        """
        Возвращает список доменов, упорядоченный по id.
        """

        query = self._session.query(Domain).order_by(Domain.id)
        if limit is not None:
            query = query.limit(limit)
        return [record.domain for record in query.all()]
