from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
from datetime import datetime

from src.audit_modules.types import AuditContext, CheckUpdate, ModuleResult
from src.webapp_db import CheckRow

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
        try:
            cert = await asyncio.to_thread(_fetch_certificate)
            evidence["certificate"] = _normalize_cert(cert)
            logger.info("[tls] сертификат получен для %s", context.domain)
            row = CheckRow(
                status="yes",
                score=100,
                evidence_json=json.dumps(evidence, ensure_ascii=False),
            )
        except (ssl.SSLError, socket.error, TimeoutError) as exc:
            logger.warning("[tls] ошибка получения сертификата для %s: %s", context.domain, exc)
            evidence["error"] = str(exc)
            row = CheckRow(
                status="no",
                score=0,
                evidence_json=json.dumps(evidence, ensure_ascii=False),
            )

        return ModuleResult(
            check_updates=[
                CheckUpdate(
                    key=self.key,
                    description="Проверка TLS сертификата",
                    row=row,
                )
            ]
        )


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
