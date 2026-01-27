from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable

from sqlalchemy import Column, DateTime, Integer, String, create_engine, func
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

logger = logging.getLogger(__name__)

Base = declarative_base()


class Domain(Base):
    """Таблица доменов для веб-интерфейса и фоновых задач."""

    __tablename__ = "domains"

    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False, unique=True)
    source = Column(String(64), nullable=False, default="manual")
    created_at = Column(DateTime, nullable=False, server_default=func.now())


@dataclass(frozen=True)
class DbState:
    """Упаковываем движок и фабрику сессий, чтобы передавать как единый объект."""

    engine: Engine
    session_factory: sessionmaker


def create_db_state(database_url: str) -> DbState:
    """
    Создаём SQLAlchemy engine и фабрику сессий.

    Держим параметры централизованно, чтобы в дальнейшем было проще масштабировать проект.
    """

    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, future=True, connect_args=connect_args)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
    logger.info("Инициализирован движок базы данных: %s", database_url)
    return DbState(engine=engine, session_factory=session_factory)


def init_db(state: DbState) -> None:
    """Создаём таблицы, если их ещё нет."""

    logger.info("Запуск миграций (create_all) для схемы веб-приложения")
    Base.metadata.create_all(state.engine)


def create_domain(session: Session, domain: str, source: str = "manual") -> Domain:
    """
    Добавляет домен в базу, если он отсутствует.

    Возвращает объект Domain, чтобы его можно было использовать в логах/ответах.
    """

    normalized = domain.strip().lower()
    logger.debug("Нормализация домена: raw=%s normalized=%s", domain, normalized)
    existing = session.query(Domain).filter(Domain.domain == normalized).one_or_none()
    if existing:
        logger.info("Домен уже существует в базе: %s", normalized)
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
