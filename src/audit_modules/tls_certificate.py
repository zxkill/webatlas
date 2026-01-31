from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
import time
from datetime import datetime

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AuditContext, CheckUpdate, ModuleResult
from src.webapp_db import Base, CheckRow, Domain, create_domain

logger = logging.getLogger(__name__)


class TlsCertificateModule:
    """Модуль проверки TLS-сертификата домена."""

    key = "tls_certificate"
    name = "TLS сертификат"
    description = "Проверяет наличие и параметры TLS-сертификата на 443 порту."
    depends_on: tuple[str, ...] = ()

    async def run(self, context: AuditContext) -> ModuleResult:
        """
        Проверяет TLS-сертификат, используя отдельный поток для блокирующего сокета.

        Возвращает статус yes/no и подробные сведения о сертификате.
        """

        timeout = max(1, int(context.config.audit.timeouts.total))
        logger.debug("[tls] проверяем сертификат %s с таймаутом %s", context.domain, timeout)

        def _fetch_certificate() -> dict:
            # Блокирующий код получения сертификата через SSL-сокет.
            context_ssl = ssl.create_default_context()
            with socket.create_connection((context.domain, 443), timeout=timeout) as sock:
                with context_ssl.wrap_socket(sock, server_hostname=context.domain) as ssock:
                    cert = ssock.getpeercert()
            return cert

        evidence: dict = {"domain": context.domain}
        module_payload: list[dict] = []
        try:
            cert = await asyncio.to_thread(_fetch_certificate)
            evidence["certificate"] = _normalize_cert(cert)
            logger.info("[tls] сертификат получен для %s", context.domain)
            row = CheckRow(
                status="yes",
                score=100,
                evidence_json=json.dumps(evidence, ensure_ascii=False),
            )
            module_payload.append(
                {
                    "checked_ts": int(time.time()),
                    "status": "yes",
                    "not_after": evidence["certificate"].get("notAfter"),
                    "issuer": json.dumps(evidence["certificate"].get("issuer"), ensure_ascii=False),
                    "evidence_json": json.dumps(evidence, ensure_ascii=False),
                }
            )
        except (ssl.SSLError, socket.error, TimeoutError) as exc:
            logger.warning("[tls] ошибка получения сертификата для %s: %s", context.domain, exc)
            evidence["error"] = str(exc)
            row = CheckRow(
                status="no",
                score=0,
                evidence_json=json.dumps(evidence, ensure_ascii=False),
            )
            module_payload.append(
                {
                    "checked_ts": int(time.time()),
                    "status": "no",
                    "not_after": None,
                    "issuer": None,
                    "evidence_json": json.dumps(evidence, ensure_ascii=False),
                }
            )

        return ModuleResult(
            check_updates=[
                CheckUpdate(
                    key=self.key,
                    description="Проверка TLS сертификата",
                    row=row,
                )
            ],
            module_payload=module_payload,
        )

    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        """
        Сохраняет результаты TLS проверки в таблицу tls_certificate_checks.
        """

        if not payload:
            logger.debug("[tls] нет данных для сохранения по домену %s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[tls] домен %s отсутствовал, создаём запись перед сохранением", domain)
            domain_record = create_domain(session, domain, source="audit")

        for item in payload:
            session.add(
                TlsCertificateCheck(
                    domain_id=domain_record.id,
                    checked_ts=item.get("checked_ts", int(time.time())),
                    status=item.get("status", "no"),
                    not_after=item.get("not_after"),
                    issuer=item.get("issuer"),
                    evidence_json=item.get("evidence_json"),
                )
        )
        session.commit()
        logger.info("[tls] сохранены проверки TLS: domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        """
        Формирует блок отчёта по TLS, показывая последние 5 проверок.
        """

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "entries": [],
                "empty_message": "Данные о домене отсутствуют в базе.",
            }

        rows = (
            session.query(TlsCertificateCheck)
            .filter(TlsCertificateCheck.domain_id == domain_record.id)
            .order_by(TlsCertificateCheck.checked_ts.desc())
            .limit(5)
            .all()
        )

        entries = []
        for row in rows:
            timestamp = datetime.fromtimestamp(row.checked_ts).strftime("%d.%m.%Y %H:%M:%S")
            if row.status == "yes":
                message = f"сертификат получен, срок до {row.not_after or 'не указан'}"
            else:
                message = "сертификат не получен"
            entries.append({"timestamp": timestamp, "status": row.status, "message": message, "details": {}})

        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "entries": entries,
            "empty_message": "Проверки TLS ещё не выполнялись.",
        }


class TlsCertificateCheck(Base):
    """Таблица результатов проверки TLS сертификата."""

    __tablename__ = "tls_certificate_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    checked_ts = Column(Integer, nullable=False)
    status = Column(String(32), nullable=False)
    not_after = Column(String(128), nullable=True)
    issuer = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=True)


def _normalize_cert(cert: dict) -> dict:
    """Нормализует данные сертификата для сохранения в JSON."""

    normalized: dict = {
        "subject": cert.get("subject"),
        "issuer": cert.get("issuer"),
        "serialNumber": cert.get("serialNumber"),
        "version": cert.get("version"),
        "subjectAltName": cert.get("subjectAltName"),
    }

    for field in ("notBefore", "notAfter"):
        value = cert.get(field)
        if value:
            try:
                normalized[field] = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").isoformat()
            except ValueError:
                normalized[field] = value
        else:
            normalized[field] = None

    return normalized
