from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Iterable, Optional

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    func,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

from src.domain_utils import load_domains_from_file

logger = logging.getLogger(__name__)

Base = declarative_base()


class Domain(Base):
    """Таблица доменов для веб-интерфейса и фоновых задач."""

    __tablename__ = "domains"

    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False, unique=True)
    source = Column(String(64), nullable=False, default="manual")
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    checks = relationship("DomainCheck", back_populates="domain")
    cms_records = relationship("DomainCms", back_populates="domain")
    admin_panels = relationship("AdminPanel", back_populates="domain")


class Check(Base):
    """Справочник типов проверок (например, Bitrix)."""

    __tablename__ = "checks"

    id = Column(Integer, primary_key=True)
    key = Column(String(128), nullable=False, unique=True)
    description = Column(Text, nullable=True)

    domain_checks = relationship("DomainCheck", back_populates="check")


class DomainCheck(Base):
    """Связь домена и проверки с результатами выполнения."""

    __tablename__ = "domain_checks"
    __table_args__ = (UniqueConstraint("domain_id", "check_id", name="uq_domain_check"),)

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    check_id = Column(Integer, ForeignKey("checks.id"), nullable=False)
    status = Column(String(32), nullable=True)
    score = Column(Integer, nullable=False, default=0)
    evidence_json = Column(Text, nullable=True)
    last_checked_ts = Column(Integer, nullable=True)

    domain = relationship("Domain", back_populates="checks")
    check = relationship("Check", back_populates="domain_checks")


class Cms(Base):
    """Справочник CMS/фреймворков."""

    __tablename__ = "cms"

    id = Column(Integer, primary_key=True)
    key = Column(String(128), nullable=False, unique=True)
    name = Column(String(255), nullable=False)

    domain_cms = relationship("DomainCms", back_populates="cms")


class DomainCms(Base):
    """Связь домена и CMS с результатами определения."""

    __tablename__ = "domain_cms"
    __table_args__ = (UniqueConstraint("domain_id", "cms_id", name="uq_domain_cms"),)

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    cms_id = Column(Integer, ForeignKey("cms.id"), nullable=False)
    status = Column(String(32), nullable=True)
    confidence = Column(Integer, nullable=False, default=0)
    evidence_json = Column(Text, nullable=True)
    last_checked_ts = Column(Integer, nullable=True)

    domain = relationship("Domain", back_populates="cms_records")
    cms = relationship("Cms", back_populates="domain_cms")


class AdminPanel(Base):
    """Таблица доступности админок для домена."""

    __tablename__ = "admin_panels"
    __table_args__ = (UniqueConstraint("domain_id", "panel_key", name="uq_admin_panel"),)

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    panel_key = Column(String(128), nullable=False)
    status = Column(String(32), nullable=True)
    http_status = Column(Integer, nullable=True)
    final_url = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=True)
    last_checked_ts = Column(Integer, nullable=True)

    domain = relationship("Domain", back_populates="admin_panels")


@dataclass(frozen=True)
class DbState:
    """Упаковываем движок и фабрику сессий, чтобы передавать как единый объект."""

    engine: Engine
    session_factory: sessionmaker


@dataclass(frozen=True)
class CheckRow:
    """Результат проверки домена, используется для записи в БД."""

    status: str
    score: int
    evidence_json: str


@dataclass(frozen=True)
class AdminPanelRow:
    """Результат проверки админки домена."""

    status: Optional[str]
    http_status: Optional[int]
    final_url: Optional[str]
    evidence_json: str


@dataclass(frozen=True)
class CmsRow:
    """Результат определения CMS домена."""

    status: str
    confidence: int
    evidence_json: str


@dataclass(frozen=True)
class FileImportStats:
    """Статистика импорта доменов из файла."""

    total_lines: int
    normalized_domains: int
    unique_domains: int
    inserted_domains: int
    skipped_duplicates: int


def create_db_state(database_url: str) -> DbState:
    """
    Создаём SQLAlchemy engine и фабрику сессий.

    Держим параметры централизованно, чтобы в дальнейшем было проще масштабировать проект.
    """

    engine = create_engine(database_url, future=True)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
    logger.info("Инициализирован движок базы данных: %s", database_url)
    return DbState(engine=engine, session_factory=session_factory)


def init_db(state: DbState) -> None:
    """Создаём таблицы, если их ещё нет."""

    logger.info("Запуск миграций (create_all) для схемы веб-приложения")
    Base.metadata.create_all(state.engine)


def create_domain(session: Session, domain: str, source: str = "manual") -> Domain:
    """
    Добавляет домен в базу, если он отсутствует, иначе обновляет источник.

    Возвращает объект Domain, чтобы его можно было использовать в логах/ответах.
    """

    normalized = domain.strip().lower()
    logger.debug("Нормализация домена: raw=%s normalized=%s", domain, normalized)
    existing = session.query(Domain).filter(Domain.domain == normalized).one_or_none()
    if existing:
        logger.info("Домен уже существует в базе: %s", normalized)
        existing.source = source
        existing.updated_at = func.now()
        session.commit()
        return existing

    record = Domain(domain=normalized, source=source)
    session.add(record)
    session.commit()
    session.refresh(record)
    logger.info("Создан новый домен: %s", normalized)
    return record


def list_domains(session: Session, limit: int = 100) -> Iterable[Domain]:
    """Возвращает последние добавленные домены для отображения в веб-UI."""

    logger.debug("Загрузка доменов для UI, limit=%s", limit)
    return session.query(Domain).order_by(Domain.id.desc()).limit(limit).all()


def _get_or_create_domain(session: Session, domain: str) -> Domain:
    """Внутренний помощник: гарантирует наличие домена в базе."""

    normalized = domain.strip().lower()
    record = session.query(Domain).filter(Domain.domain == normalized).one_or_none()
    if record:
        return record
    logger.info("Домен отсутствовал в базе и будет создан: %s", normalized)
    record = Domain(domain=normalized, source="audit")
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


def _get_or_create_check(session: Session, key: str, description: Optional[str]) -> Check:
    """Создаём описание проверки, если оно ещё не зарегистрировано."""

    record = session.query(Check).filter(Check.key == key).one_or_none()
    if record:
        if description and record.description != description:
            record.description = description
            session.commit()
        return record
    record = Check(key=key, description=description)
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


def _get_or_create_cms(session: Session, key: str, name: str) -> Cms:
    """Создаём запись CMS при необходимости."""

    record = session.query(Cms).filter(Cms.key == key).one_or_none()
    if record:
        if record.name != name:
            record.name = name
            session.commit()
        return record
    record = Cms(key=key, name=name)
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


def update_check(
    session: Session,
    domain: str,
    check_key: str,
    row: CheckRow,
    description: Optional[str] = None,
) -> None:
    """
    Обновляет результаты конкретной проверки (например, Bitrix) в PostgreSQL.
    """

    domain_record = _get_or_create_domain(session, domain)
    check_record = _get_or_create_check(session, check_key, description)
    record = (
        session.query(DomainCheck)
        .filter(DomainCheck.domain_id == domain_record.id, DomainCheck.check_id == check_record.id)
        .one_or_none()
    )
    timestamp = int(time.time())
    if record:
        record.status = row.status
        record.score = row.score
        record.evidence_json = row.evidence_json
        record.last_checked_ts = timestamp
    else:
        record = DomainCheck(
            domain_id=domain_record.id,
            check_id=check_record.id,
            status=row.status,
            score=row.score,
            evidence_json=row.evidence_json,
            last_checked_ts=timestamp,
        )
        session.add(record)
    session.commit()
    logger.info("Обновлён результат проверки %s для домена %s", check_key, domain)


def update_admin_panel(session: Session, domain: str, panel_key: str, row: AdminPanelRow) -> None:
    """Обновляет статус доступности админки."""

    domain_record = _get_or_create_domain(session, domain)
    record = (
        session.query(AdminPanel)
        .filter(AdminPanel.domain_id == domain_record.id, AdminPanel.panel_key == panel_key)
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
        record = AdminPanel(
            domain_id=domain_record.id,
            panel_key=panel_key,
            status=row.status,
            http_status=row.http_status,
            final_url=row.final_url,
            evidence_json=row.evidence_json,
            last_checked_ts=timestamp,
        )
        session.add(record)
    session.commit()
    logger.info("Обновлён статус админки %s для домена %s", panel_key, domain)


def update_domain_cms(session: Session, domain: str, cms_key: str, cms_name: str, row: CmsRow) -> None:
    """Фиксирует результаты определения CMS для домена."""

    domain_record = _get_or_create_domain(session, domain)
    cms_record = _get_or_create_cms(session, cms_key, cms_name)
    record = (
        session.query(DomainCms)
        .filter(DomainCms.domain_id == domain_record.id, DomainCms.cms_id == cms_record.id)
        .one_or_none()
    )
    timestamp = int(time.time())
    if record:
        record.status = row.status
        record.confidence = row.confidence
        record.evidence_json = row.evidence_json
        record.last_checked_ts = timestamp
    else:
        record = DomainCms(
            domain_id=domain_record.id,
            cms_id=cms_record.id,
            status=row.status,
            confidence=row.confidence,
            evidence_json=row.evidence_json,
            last_checked_ts=timestamp,
        )
        session.add(record)
    session.commit()
    logger.info("Обновлена CMS %s для домена %s", cms_key, domain)


def import_domains_from_file(session: Session, path: str, source: str = "file") -> FileImportStats:
    """Импортируем домены из файла и возвращаем статистику."""

    logger.info("Запуск импорта доменов через админку: %s", path)
    domains = load_domains_from_file(path)
    unique_domains = set(domains)
    inserted = 0
    for domain in unique_domains:
        create_domain(session, domain, source=source)
        inserted += 1

    stats = FileImportStats(
        total_lines=_count_lines(path),
        normalized_domains=len(domains),
        unique_domains=len(unique_domains),
        inserted_domains=inserted,
        skipped_duplicates=len(domains) - len(unique_domains),
    )
    logger.info(
        "Импорт завершён: lines=%s normalized=%s unique=%s inserted=%s duplicates=%s",
        stats.total_lines,
        stats.normalized_domains,
        stats.unique_domains,
        stats.inserted_domains,
        stats.skipped_duplicates,
    )
    return stats


def get_domain_report(session: Session, domain: str) -> Optional[dict]:
    """Формирует агрегированный отчёт по домену для админки."""

    normalized = domain.strip().lower()
    record = session.query(Domain).filter(Domain.domain == normalized).one_or_none()
    if record is None:
        logger.warning("Запрошен отчёт по домену, который не найден: %s", normalized)
        return None

    checks_payload = [
        {
            "key": item.check.key,
            "description": item.check.description,
            "status": item.status,
            "score": item.score,
            "evidence_json": item.evidence_json,
            "last_checked_ts": item.last_checked_ts,
        }
        for item in record.checks
    ]
    cms_payload = [
        {
            "key": item.cms.key,
            "name": item.cms.name,
            "status": item.status,
            "confidence": item.confidence,
            "evidence_json": item.evidence_json,
            "last_checked_ts": item.last_checked_ts,
        }
        for item in record.cms_records
    ]
    admin_payload = [
        {
            "panel_key": item.panel_key,
            "status": item.status,
            "http_status": item.http_status,
            "final_url": item.final_url,
            "evidence_json": item.evidence_json,
            "last_checked_ts": item.last_checked_ts,
        }
        for item in record.admin_panels
    ]

    report = {
        "domain": record.domain,
        "source": record.source,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
        "checks": checks_payload,
        "cms": cms_payload,
        "admin_panels": admin_payload,
    }
    logger.info("Сформирован отчёт по домену: %s", normalized)
    return report


def _count_lines(path: str) -> int:
    """Вспомогательная функция для подсчёта строк в файле."""

    with open(path, "r", encoding="utf-8") as handle:
        return sum(1 for _ in handle)
