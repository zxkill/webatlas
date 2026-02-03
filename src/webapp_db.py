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
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    func,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

from src.utils.domain_import import import_domains_via_copy

logger = logging.getLogger(__name__)

Base = declarative_base()

# Временная staging-таблица для быстрого COPY-импорта доменов.
# Важно: без первичного ключа и индексов, чтобы загрузка была максимально быстрой.
domains_staging_table = Table(
    "domains_staging",
    Base.metadata,
    Column("domain", Text, nullable=False),
)


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
    module_runs = relationship("ModuleRun", back_populates="domain", order_by="ModuleRun.id")


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


class ModuleRun(Base):
    """Таблица фиксации результатов запуска модулей аудита."""

    __tablename__ = "module_runs"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    module_key = Column(String(128), nullable=False)
    module_name = Column(String(255), nullable=False)
    status = Column(String(32), nullable=False)
    started_ts = Column(Integer, nullable=False)
    finished_ts = Column(Integer, nullable=False)
    duration_ms = Column(Integer, nullable=False)
    detail_json = Column(Text, nullable=False)
    error_message = Column(Text, nullable=True)

    domain = relationship("Domain", back_populates="module_runs")


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
class ModuleRunRow:
    """Результат выполнения модуля для записи в БД."""

    module_key: str
    module_name: str
    status: str
    started_ts: int
    finished_ts: int
    duration_ms: int
    detail_json: str
    error_message: Optional[str] = None


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

    # Подгружаем модули аудита заранее, чтобы их таблицы зарегистрировались в Base.metadata.
    # Это гарантирует, что create_all создаст таблицы модулей при старте приложения.
    try:
        from src.audit_modules import registry  # noqa: F401
    except Exception:  # noqa: BLE001 - не ломаем запуск из-за ошибки импорта
        logger.exception("Не удалось импортировать audit_modules перед созданием схемы")
    logger.info("Запуск миграций (create_all) для схемы веб-приложения")
    Base.metadata.create_all(state.engine)


def create_domain(session: Session, domain: str, source: str = "manual", *, commit: bool = True) -> Domain:
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
        if commit:
            session.commit()
        return existing

    record = Domain(domain=normalized, source=source)
    session.add(record)
    session.flush()
    session.refresh(record)
    logger.info("Создан новый домен: %s", normalized)
    if commit:
        session.commit()
    return record


def list_domains(session: Session, limit: int = 100) -> Iterable[Domain]:
    """Возвращает последние добавленные домены для отображения в веб-UI."""

    logger.debug("Загрузка доменов для UI, limit=%s", limit)
    return session.query(Domain).order_by(Domain.id.desc()).limit(limit).all()


def _get_or_create_domain(session: Session, domain: str, *, commit: bool = True) -> Domain:
    """Внутренний помощник: гарантирует наличие домена в базе."""

    normalized = domain.strip().lower()
    record = session.query(Domain).filter(Domain.domain == normalized).one_or_none()
    if record:
        return record

    logger.info("Домен отсутствовал в базе и будет создан: %s", normalized)
    record = Domain(domain=normalized, source="audit")
    session.add(record)
    session.flush()
    session.refresh(record)
    if commit:
        session.commit()
    return record


def _get_or_create_check(session: Session, key: str, description: Optional[str], *, commit: bool = True) -> Check:
    """Создаём описание проверки, если оно ещё не зарегистрировано."""

    record = session.query(Check).filter(Check.key == key).one_or_none()
    if record:
        if description and record.description != description:
            record.description = description
            if commit:
                session.commit()
        return record

    record = Check(key=key, description=description)
    session.add(record)
    session.flush()
    session.refresh(record)
    if commit:
        session.commit()
    return record


def _get_or_create_cms(session: Session, key: str, name: str, *, commit: bool = True) -> Cms:
    """Создаём запись CMS при необходимости."""

    record = session.query(Cms).filter(Cms.key == key).one_or_none()
    if record:
        if record.name != name:
            record.name = name
            if commit:
                session.commit()
        return record

    record = Cms(key=key, name=name)
    session.add(record)
    session.flush()
    session.refresh(record)
    if commit:
        session.commit()
    return record


def update_check(
    session: Session,
    domain: str,
    check_key: str,
    row: CheckRow,
    description: Optional[str] = None,
    *,
    commit: bool = True,
) -> None:
    """
    Обновляет результаты конкретной проверки (например, Bitrix) в PostgreSQL.

    commit=True (по умолчанию) сохраняет поведение прежней версии.
    Для пакетной записи в конце домена используйте commit=False.
    """

    domain_record = _get_or_create_domain(session, domain, commit=commit)
    check_record = _get_or_create_check(session, check_key, description, commit=commit)

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

    if commit:
        session.commit()
    logger.info("Обновлён результат проверки %s для домена %s", check_key, domain)


def update_admin_panel(
    session: Session,
    domain: str,
    panel_key: str,
    row: AdminPanelRow,
    *,
    commit: bool = True,
) -> None:
    """
    Обновляет статус доступности админки.

    commit=True (по умолчанию) сохраняет прежнее поведение.
    Для пакетной записи в конце домена используйте commit=False.
    """

    domain_record = _get_or_create_domain(session, domain, commit=commit)

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

    if commit:
        session.commit()
    logger.info("Обновлён статус админки %s для домена %s", panel_key, domain)


def update_domain_cms(
    session: Session,
    domain: str,
    cms_key: str,
    cms_name: str,
    row: CmsRow,
    *,
    commit: bool = True,
) -> None:
    """
    Фиксирует результаты определения CMS для домена.

    commit=True (по умолчанию) сохраняет прежнее поведение.
    Для пакетной записи в конце домена используйте commit=False.
    """

    domain_record = _get_or_create_domain(session, domain, commit=commit)
    cms_record = _get_or_create_cms(session, cms_key, cms_name, commit=commit)

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

    if commit:
        session.commit()
    logger.info("Обновлена CMS %s для домена %s", cms_key, domain)


def update_module_run(
    session: Session,
    domain: str,
    row: ModuleRunRow,
    *,
    commit: bool = True,
) -> None:
    """
    Сохраняем запуск модуля в отдельную таблицу module_runs.

    commit=True (по умолчанию) сохраняет прежнее поведение.
    Для пакетной записи в конце домена используйте commit=False.
    """

    domain_record = _get_or_create_domain(session, domain, commit=commit)
    record = ModuleRun(
        domain_id=domain_record.id,
        module_key=row.module_key,
        module_name=row.module_name,
        status=row.status,
        started_ts=row.started_ts,
        finished_ts=row.finished_ts,
        duration_ms=row.duration_ms,
        detail_json=row.detail_json,
        error_message=row.error_message,
    )
    session.add(record)

    if commit:
        session.commit()
    logger.info(
        "Зафиксирован запуск модуля %s для домена %s (status=%s)",
        row.module_key,
        domain,
        row.status,
    )


def import_domains_from_file(session: Session, path: str, source: str = "file") -> FileImportStats:
    """Импортируем домены из файла и возвращаем статистику."""

    logger.info("Запуск быстрого импорта доменов через админку: %s", path)

    # Используем прямое соединение DB-API, чтобы выполнить COPY максимально быстро.
    raw_connection = session.get_bind().raw_connection()
    try:
        copy_stats = import_domains_via_copy(raw_connection, path, source, log=logger)
    finally:
        raw_connection.close()

    stats = FileImportStats(
        total_lines=copy_stats.total_lines,
        normalized_domains=copy_stats.normalized_domains,
        unique_domains=copy_stats.unique_domains,
        inserted_domains=copy_stats.inserted_domains,
        skipped_duplicates=copy_stats.skipped_duplicates,
    )
    logger.info(
        "Импорт завершён: lines=%s normalized=%s unique=%s inserted=%s skipped=%s",
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
    module_runs_payload = [
        {
            "module_key": item.module_key,
            "module_name": item.module_name,
            "status": item.status,
            "started_ts": item.started_ts,
            "finished_ts": item.finished_ts,
            "duration_ms": item.duration_ms,
            "detail_json": item.detail_json,
            "error_message": item.error_message,
        }
        for item in record.module_runs
    ]

    # Формируем блоки отчёта из каждого модуля, чтобы UI был модульным.
    module_blocks = []
    try:
        from src.audit_modules.registry import list_modules

        for module in list_modules():
            module_blocks.append(module.build_report_block(session, normalized))
    except Exception:  # noqa: BLE001 - важно не ломать отчёт из-за одного модуля
        logger.exception("Ошибка формирования модульных блоков отчёта для домена: %s", normalized)

    report = {
        "domain": record.domain,
        "source": record.source,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
        "checks": checks_payload,
        "cms": cms_payload,
        "admin_panels": admin_payload,
        "module_runs": module_runs_payload,
        "module_blocks": module_blocks,
    }
    logger.info("Сформирован отчёт по домену: %s", normalized)
    return report


def iter_domains(session: Session, limit: int | None = None, batch_size: int = 10_000) -> Iterable[str]:
    """
    Потоково возвращает домены по возрастанию id, без загрузки всех записей в память.

    - yield_per(batch_size) просит SQLAlchemy читать порциями
    - stream_results=True включает server-side cursor (для многих драйверов)
    """

    query = session.query(Domain.domain).order_by(Domain.id)
    if limit is not None:
        query = query.limit(limit)

    query = query.yield_per(batch_size).execution_options(stream_results=True)

    for (domain,) in query:
        yield domain

# --- Dashboard helpers ---------------------------------------------------------

import json
from datetime import datetime, timezone


def _pill_html(status: str) -> str:
    """
    Возвращает маленький HTML-бейдж в стиле текущих pill.
    Не используем Jinja-макрос, потому что здесь нужно компактно формировать разные лейблы.
    """
    s = (status or "").lower().strip()
    if s in {"ok", "passed", "success"}:
        cls = "ok"
    elif s in {"warn", "warning", "maybe"}:
        cls = "warn"
    elif s in {"critical", "bad", "fail", "failed", "error"}:
        cls = "bad"
    else:
        cls = ""
    return f'<span class="pill {cls}"><span class="dot"></span>{status}</span>'


def _fmt_ago(ts: int | None) -> str:
    if not ts:
        return "нет данных"
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    now = datetime.now(timezone.utc)
    sec = int((now - dt).total_seconds())
    if sec < 60:
        return f"{sec} сек назад"
    if sec < 3600:
        return f"{sec // 60} мин назад"
    if sec < 86400:
        return f"{sec // 3600} ч назад"
    return f"{sec // 86400} дн назад"


def _safe_json(detail_json: str) -> dict:
    try:
        return json.loads(detail_json or "{}")
    except Exception:
        return {}


def _extract_tls_days_left(payload: dict, now_ts: int) -> int | None:
    """
    Достаёт количество дней до истечения TLS из payload.

    Поддерживаем несколько форматов, чтобы не зависеть от конкретной версии TLS-модуля.
    """

    # Наиболее прямой вариант — days_left.
    if isinstance(payload.get("days_left"), int):
        return payload["days_left"]
    if isinstance(payload.get("days_left"), str) and payload["days_left"].isdigit():
        return int(payload["days_left"])

    # Unix timestamp до окончания сертификата.
    for key in ("not_after_ts", "expires_at_ts"):
        ts = payload.get(key)
        if isinstance(ts, int) and ts > 0:
            return int((ts - now_ts) / 86400)

    # ISO даты — допускаем отсутствие tzinfo и считаем UTC.
    for key in ("not_after", "expires_at"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            try:
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return int((dt.timestamp() - now_ts) / 86400)
            except Exception:
                continue
    return None


def _build_tls_note_badge(days_left: int) -> tuple[str, str]:
    """
    Формирует пояснение и бейдж для TLS в зависимости от срока.

    Возвращает (note, badge_html).
    """

    if days_left < 0:
        return f"истёк {abs(days_left)} дн назад", '<span class="pill bad"><span class="dot"></span>expired</span>'
    if days_left <= 3:
        return f"осталось {days_left} дн", '<span class="pill bad"><span class="dot"></span>⚠</span>'
    return f"осталось {days_left} дн", '<span class="pill warn"><span class="dot"></span>soon</span>'


def _is_critical_run(run: ModuleRun) -> bool:
    """
    Проверяем, относится ли запуск к критичным (ошибки или статус failed).
    """

    status = (run.status or "").lower()
    return status in {"failed", "fail", "error", "critical", "bad"} or bool(run.error_message)


def _load_recent_runs(session: Session, *, limit: int) -> list[tuple[ModuleRun, Domain]]:
    """
    Загружает последние запуски модулей вместе с доменами.

    Это помогает получать "актуальное" состояние без тяжёлых агрегатов.
    """

    logger.debug("Загружаем последние запуски модулей: limit=%s", limit)
    return (
        session.query(ModuleRun, Domain)
        .join(Domain, Domain.id == ModuleRun.domain_id)
        .order_by(ModuleRun.id.desc())
        .limit(limit)
        .all()
    )


def _format_domain_row(domain: Domain, *, note: str | None = None, badge: str | None = None) -> dict:
    """
    Приводим доменную запись к формату, удобному для UI.

    Дополнительные поля note/badge используются в режиме "фокуса".
    """

    return {
        "id": domain.id,
        "domain": domain.domain,
        "source": domain.source,
        "note": note,
        "badge": badge,
    }


def get_dashboard_data(session: Session, *, top_n: int = 5, tls_soon_days: int = 14) -> dict:
    """
    Формирует данные для главного Dashboard.

    Источники данных (гарантированно есть сейчас):
    - domains (последние добавленные)
    - module_runs (последние запуски модулей + ошибки)

    TLS истечение:
    - best-effort: пытаемся извлечь из ModuleRun.detail_json поля:
      not_after_ts / expires_at_ts / days_left / not_after (ISO) / expires_at (ISO)
    - если данных нет, блок будет пустым с понятным empty_message

    Важно: топ-списки ограничены top_n, чтобы главная оставалась лёгкой и компактной.
    """

    logger.info("[dashboard] build payload: top_n=%s tls_soon_days=%s", top_n, tls_soon_days)

    total_domains = session.query(func.count(Domain.id)).scalar() or 0

    # Берём достаточно запусков, чтобы надёжно собрать top-списки и KPI.
    # Увеличиваем лимит пропорционально top_n, чтобы избегать "пустых" блоков.
    recent_limit = max(top_n * 20, 200)
    recent_runs = _load_recent_runs(session, limit=recent_limit)

    # Последние домены
    recent_domains_rows = (
        session.query(Domain)
        .order_by(Domain.id.desc())
        .limit(top_n)
        .all()
    )
    recent_domains = [
        {"domain": d.domain, "note": f"ID {d.id} · {d.source}"}
        for d in recent_domains_rows
    ]

    # Аудиты за 24 часа (по module_runs)
    now_ts = int(time.time())
    ts_24h = now_ts - 24 * 3600
    audits_24h = (
        session.query(func.count(ModuleRun.id))
        .filter(ModuleRun.started_ts >= ts_24h)
        .scalar()
        or 0
    )

    # Критические события: ошибки/failed
    critical_events = []
    seen_domains = set()
    critical_domains = set()

    for run, domain in recent_runs:
        if _is_critical_run(run):
            critical_domains.add(domain.domain)
            if domain.domain in seen_domains:
                continue
            seen_domains.add(domain.domain)

            note = run.error_message or f"{run.module_name} · {run.module_key}"
            badge = _pill_html(run.status)
            critical_events.append({"domain": domain.domain, "note": note, "badge": badge})
            if len(critical_events) >= top_n:
                break

    # Последние аудиты: отображаем последние успешные/любые по уникальным доменам
    recent_audits = []
    seen_domains = set()
    for run, domain in recent_runs:
        if domain.domain in seen_domains:
            continue
        seen_domains.add(domain.domain)

        note = f"{run.module_name} · {_fmt_ago(run.finished_ts)}"
        badge = _pill_html(run.status)
        recent_audits.append({"domain": domain.domain, "note": note, "badge": badge})
        if len(recent_audits) >= top_n:
            break

    # TLS soon: best-effort parsing
    tls_soon = []
    seen_domains = set()
    tls_soon_domains = set()

    # Соберём кандидаты по module_key, содержащему "tls"
    tls_candidates = []
    for run, domain in recent_runs:
        mk = (run.module_key or "").lower()
        if "tls" not in mk:
            continue
        tls_candidates.append((run, domain))

    for run, domain in tls_candidates:
        payload = _safe_json(run.detail_json)
        days_left = _extract_tls_days_left(payload, now_ts)
        if days_left is None:
            continue

        if days_left <= tls_soon_days:
            tls_soon_domains.add(domain.domain)

            if domain.domain in seen_domains:
                continue
            seen_domains.add(domain.domain)

            note, badge = _build_tls_note_badge(days_left)
            tls_soon.append({"domain": domain.domain, "note": note, "badge": badge})
            if len(tls_soon) >= top_n:
                continue

    # Критично: количество уникальных доменов с ошибками в последних N запусков
    critical_count = len(critical_domains)

    result = {
        "limits": {"top_n": top_n},
        "thresholds": {"tls_soon_days": tls_soon_days},
        "kpis": {
            "total_domains": total_domains,
            "critical_count": critical_count,
            "tls_soon_count": len(tls_soon_domains),
            "audits_24h": audits_24h,
        },
        "recent_domains": recent_domains,
        "recent_audits": recent_audits,
        "critical_events": critical_events,
        "tls_soon": tls_soon,
        "empty": {
            "recent_domains": "Доменов пока нет.",
            "recent_audits": "Нет запусков модулей аудита.",
            "critical_events": "Критичных событий не найдено.",
            "tls_soon": "Нет данных по истечению TLS (нужны поля в detail_json TLS-модуля).",
        },
    }

    logger.info(
        "[dashboard] ready: total_domains=%s audits_24h=%s recent_domains=%s recent_audits=%s critical=%s tls_soon=%s",
        total_domains,
        audits_24h,
        len(recent_domains),
        len(recent_audits),
        len(critical_events),
        len(tls_soon),
    )
    return result


def get_domains_focus_data(
    session: Session,
    *,
    focus: str | None = None,
    limit: int = 100,
    top_n: int = 50,
    tls_soon_days: int = 14,
) -> dict:
    """
    Возвращает данные для страницы доменов с учётом "фокуса".

    Фокус — это быстрый фильтр для переходов с главного экрана.
    """

    allowed_focus = {"critical", "tls_soon", "recent_audits"}
    normalized_focus = focus if focus in allowed_focus else None
    logger.info(
        "[domains] build focus payload: focus=%s limit=%s top_n=%s tls_soon_days=%s",
        normalized_focus,
        limit,
        top_n,
        tls_soon_days,
    )

    if not normalized_focus:
        # Без фокуса показываем последние домены как есть.
        domains_rows = list_domains(session, limit)
        payload = [_format_domain_row(domain) for domain in domains_rows]
        logger.debug("[domains] focus not set, rows=%s", len(payload))
        return {"domains": payload, "focus": None}

    # Загружаем последние запуски модулей для построения "актуальных" списков.
    recent_limit = max(top_n * 20, 200)
    recent_runs = _load_recent_runs(session, limit=recent_limit)
    now_ts = int(time.time())

    focus_items: list[dict] = []
    focus_set: set[str] = set()

    focus_title = ""
    focus_subtitle = ""
    focus_empty = "Нет данных по выбранному фильтру."

    if normalized_focus == "critical":
        focus_title = "Критичные домены"
        focus_subtitle = "Домены с ошибками в последних запусках модулей."

        for run, domain in recent_runs:
            if not _is_critical_run(run):
                continue
            if domain.domain in focus_set:
                continue
            focus_set.add(domain.domain)

            note = run.error_message or f"{run.module_name} · {run.module_key}"
            badge = _pill_html(run.status)
            focus_items.append(_format_domain_row(domain, note=note, badge=badge))
            if len(focus_items) >= top_n:
                break

    if normalized_focus == "tls_soon":
        focus_title = f"TLS ≤ {tls_soon_days} дней"
        focus_subtitle = "Доменам потребуется продление сертификата."

        for run, domain in recent_runs:
            mk = (run.module_key or "").lower()
            if "tls" not in mk:
                continue
            payload = _safe_json(run.detail_json)
            days_left = _extract_tls_days_left(payload, now_ts)
            if days_left is None or days_left > tls_soon_days:
                continue
            if domain.domain in focus_set:
                continue
            focus_set.add(domain.domain)

            note, badge = _build_tls_note_badge(days_left)
            focus_items.append(_format_domain_row(domain, note=note, badge=badge))
            if len(focus_items) >= top_n:
                break

    if normalized_focus == "recent_audits":
        focus_title = "Аудиты за 24 часа"
        focus_subtitle = "Домены с последними запусками аудита."
        ts_24h = now_ts - 24 * 3600

        for run, domain in recent_runs:
            if run.finished_ts < ts_24h:
                continue
            if domain.domain in focus_set:
                continue
            focus_set.add(domain.domain)

            note = f"{run.module_name} · {_fmt_ago(run.finished_ts)}"
            badge = _pill_html(run.status)
            focus_items.append(_format_domain_row(domain, note=note, badge=badge))
            if len(focus_items) >= top_n:
                break

    focus_payload = {
        "key": normalized_focus,
        "title": focus_title,
        "subtitle": focus_subtitle,
        "count": len(focus_items),
        "items": focus_items,
        "empty_message": focus_empty,
    }
    logger.info(
        "[domains] focus ready: key=%s items=%s recent_limit=%s",
        normalized_focus,
        len(focus_items),
        recent_limit,
    )
    return {"domains": focus_items, "focus": focus_payload}
