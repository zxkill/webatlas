from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AuditContext, CheckUpdate, ModuleResult
from src.webapp_db import Base, CheckRow, Domain, create_domain

logger = logging.getLogger(__name__)


# ----------------------------
# Конфигурация и константы
# ----------------------------

_TLS_VERSIONS_ORDER = [
    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
]

_WEAK_CIPHER_MARKERS = (
    "RC4",
    "3DES",
    "DES",
    "NULL",
    "EXPORT",
    "MD5",
)

_MAX_REDIRECTS = 3


# ----------------------------
# Вспомогательные структуры
# ----------------------------

@dataclass
class TlsFinding:
    label: str
    status: str  # ok | warning | critical | info
    message: str = ""
    details: Optional[dict] = None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _parse_cert_time(value: Optional[str]) -> Optional[datetime]:
    """
    ssl.getpeercert() возвращает notBefore/notAfter строками формата:
      "Jun  1 12:00:00 2026 GMT"
    """
    if not value:
        return None
    try:
        dt = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _days_left(not_after: Optional[datetime]) -> Optional[int]:
    if not not_after:
        return None
    delta = not_after - _now_utc()
    return int(delta.total_seconds() // 86400)


def _classify_expiry(days_left: Optional[int]) -> tuple[str, str]:
    """
    Возвращает (status, message) для срока действия.
    """
    if days_left is None:
        return ("info", "Срок действия не удалось определить (диагностика).")
    if days_left < 0:
        return ("critical", f"Сертификат истёк {abs(days_left)} дн. назад.")
    if days_left < 7:
        return ("critical", f"Сертификат истекает через {days_left} дн.")
    if days_left < 30:
        return ("warning", f"Сертификат истекает через {days_left} дн.")
    return ("ok", f"Сертификат действителен ещё {days_left} дн.")


def _is_cipher_weak(cipher_name: str) -> bool:
    up = (cipher_name or "").upper()
    return any(marker in up for marker in _WEAK_CIPHER_MARKERS)


def _score_from_findings(findings: list[TlsFinding]) -> int:
    """
    Простая и предсказуемая модель баллов:
      critical: -35
      warning:  -15
      info:      0
      ok:        0
    Ограничиваем [0..100]
    """
    score = 100
    for f in findings:
        if f.status == "critical":
            score -= 35
        elif f.status == "warning":
            score -= 15
    return max(0, min(100, score))


def _overall_status(findings: list[TlsFinding]) -> str:
    """
    Приоритет статусов: critical > warning > ok > info
    """
    has_critical = any(f.status == "critical" for f in findings)
    if has_critical:
        return "critical"
    has_warning = any(f.status == "warning" for f in findings)
    if has_warning:
        return "warning"
    has_ok = any(f.status == "ok" for f in findings)
    if has_ok:
        return "ok"
    return "info"


def _make_summary(findings: list[TlsFinding], days_left_val: Optional[int]) -> str:
    """
    Короткая человеческая строка для summary.
    """
    expiry_status, expiry_msg = _classify_expiry(days_left_val)
    # Для “интуитивности”: в первую очередь срок + наиболее критичная проблема
    top_issue = next((f for f in findings if f.status == "critical"), None) or \
                next((f for f in findings if f.status == "warning"), None)
    if top_issue and top_issue.message:
        return f"{expiry_msg} {top_issue.message}"
    return expiry_msg


# ----------------------------
# Основная реализация модуля
# ----------------------------

class TlsCertificateModule:
    """Модуль проверки TLS-сертификата домена (443), с расширенными проверками и отчётом."""

    key = "tls_certificate"
    name = "TLS и сертификат"
    description = "Проверяет валидность TLS, срок действия сертификата, версии TLS, шифр и HSTS."
    depends_on: tuple[str, ...] = ()

    async def run(self, context: AuditContext) -> ModuleResult:
        """
        Выполняет:
        - TLS handshake + получение сертификата (leaf)
        - Вычисление days_left и классификация риска
        - Проверка поддерживаемых TLS версий (best-effort)
        - Получение negotiated cipher
        - Проверка HSTS через HTTPS HEAD/GET (best-effort)
        - (Диагностика) цепочка сертификатов, если доступна в runtime
        """

        timeout = max(1, int(context.config.audit.timeouts.total))
        domain = context.domain

        logger.info("[tls] старт проверки: domain=%s timeout=%ss", domain, timeout)

        def _probe_tls() -> dict:
            """
            Блокирующий TLS-probe (в отдельном потоке), чтобы не блокировать event loop.
            Возвращает:
              - cert (raw)
              - tls_version (negotiated)
              - cipher (tuple)
              - chain_len (optional, diagnostic)
              - chain_subjects (optional, diagnostic)
            """
            ctx = ssl.create_default_context()

            # Важно: validate hostname по умолчанию в create_default_context() включён
            # (если check_hostname=True), и verify_mode = CERT_REQUIRED.
            # Это хорошо: получаем честный "валиден/невалиден".
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()  # например "TLSv1.3"
                    cipher = ssock.cipher()        # (name, protocol, secret_bits)

                    # Диагностика: в зависимости от версии Python/OpenSSL могут быть доступны методы цепочки
                    chain_len = None
                    chain_subjects = None

                    # Python 3.11+: у SSLObject/SSLSocket могут быть разные методы
                    if hasattr(ssock, "get_verified_chain"):
                        try:
                            chain = ssock.get_verified_chain()
                            chain_len = len(chain) if chain else 0
                            chain_subjects = []
                            for c in chain or []:
                                # c может быть OpenSSL.X509 или bytes в зависимости от сборки
                                chain_subjects.append(str(getattr(c, "subject", None) or type(c).__name__))
                        except Exception as exc:
                            logger.debug("[tls] chain diagnostic failed: %s", exc)

                    return {
                        "cert": cert,
                        "tls_version": tls_version,
                        "cipher": cipher,
                        "chain_len": chain_len,
                        "chain_subjects": chain_subjects,
                    }

        def _probe_tls_versions() -> dict:
            """
            Best-effort: пытаемся зафиксировать, какие версии TLS сервер принимает.
            Возвращает dict вида:
              {"TLSv1.0": true/false, ...}
            """
            results: dict[str, bool] = {}
            for label, ver in _TLS_VERSIONS_ORDER:
                if ver is None:
                    results[label] = False
                    continue
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = True
                    ctx.verify_mode = ssl.CERT_REQUIRED
                    ctx.load_default_certs()

                    # Жёстко фиксируем версию
                    ctx.minimum_version = ver
                    ctx.maximum_version = ver

                    with socket.create_connection((domain, 443), timeout=timeout) as sock:
                        with ctx.wrap_socket(sock, server_hostname=domain):
                            results[label] = True
                except Exception:
                    results[label] = False
            return results

        def _fetch_hsts() -> dict:
            """
            Best-effort: проверяем наличие Strict-Transport-Security.
            Делаем HTTPS запрос (HEAD, затем GET при необходимости).
            Следуем до _MAX_REDIRECTS редиректов.
            """
            import http.client

            url = f"https://{domain}/"
            current = url
            redirects = 0
            visited = [current]

            def _do_request(u: str) -> tuple[int, dict[str, str], str]:
                parsed = urlparse(u)
                host = parsed.hostname or domain
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"

                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)

                # HEAD чаще достаточно; если сервер не умеет — fallback на GET
                for method in ("HEAD", "GET"):
                    try:
                        conn.request(method, path, headers={"User-Agent": "webatlas-audit/1.0"})
                        resp = conn.getresponse()
                        body = ""
                        try:
                            body = resp.read(0).decode("utf-8", errors="ignore")
                        except Exception:
                            body = ""
                        headers = {k.lower(): v for k, v in resp.getheaders()}
                        return resp.status, headers, body
                    except Exception as exc:
                        logger.debug("[tls] hsts %s request failed: %s", method, exc)
                        continue
                    finally:
                        try:
                            conn.close()
                        except Exception:
                            pass

                # Полный фейл
                return 0, {}, ""

            while True:
                status, headers, _ = _do_request(current)
                hsts = headers.get("strict-transport-security")

                # Редиректы
                if status in (301, 302, 303, 307, 308) and redirects < _MAX_REDIRECTS:
                    loc = headers.get("location")
                    if not loc:
                        break
                    next_url = urljoin(current, loc)
                    # Если вдруг уводит на http — это важный сигнал
                    visited.append(next_url)
                    redirects += 1
                    current = next_url
                    continue

                return {
                    "final_url": current,
                    "visited": visited,
                    "status_code": status,
                    "hsts": hsts,
                }

        # Данные, которые пойдут в evidence_json (прозрачно и отлаживаемо)
        evidence: dict[str, Any] = {"domain": domain}

        findings: list[TlsFinding] = []
        secondary_notes: list[dict] = []  # diagnostics

        try:
            probe = await asyncio.to_thread(_probe_tls)
            cert_raw = probe.get("cert") or {}
            tls_version = probe.get("tls_version")
            cipher_tuple = probe.get("cipher") or (None, None, None)
            cipher_name = cipher_tuple[0] or ""

            evidence["certificate"] = _normalize_cert(cert_raw)
            evidence["negotiated_tls_version"] = tls_version
            evidence["negotiated_cipher"] = {
                "name": cipher_tuple[0],
                "protocol": cipher_tuple[1],
                "bits": cipher_tuple[2],
            }

            # --- Сертификат: срок действия ---
            not_after_dt = _parse_cert_time(cert_raw.get("notAfter"))
            days_left_val = _days_left(not_after_dt)
            expiry_status, expiry_msg = _classify_expiry(days_left_val)

            findings.append(TlsFinding(label="Срок действия", status=expiry_status, message=expiry_msg, details={
                "not_after": not_after_dt.isoformat() if not_after_dt else None,
                "days_left": days_left_val,
            }))

            # --- TLS версия (факт) ---
            if tls_version in ("TLSv1", "TLSv1.1"):
                findings.append(TlsFinding(
                    label="Negotiated TLS",
                    status="warning",
                    message=f"Согласована устаревшая версия {tls_version}.",
                    details={"tls_version": tls_version},
                ))
            else:
                findings.append(TlsFinding(
                    label="Negotiated TLS",
                    status="ok",
                    message=f"Согласована версия {tls_version}.",
                    details={"tls_version": tls_version},
                ))

            # --- Cipher (факт) ---
            if cipher_name and _is_cipher_weak(cipher_name):
                findings.append(TlsFinding(
                    label="Шифр",
                    status="warning",
                    message=f"Обнаружен потенциально слабый шифр: {cipher_name}.",
                    details=evidence["negotiated_cipher"],
                ))
            elif cipher_name:
                findings.append(TlsFinding(
                    label="Шифр",
                    status="ok",
                    message=f"Используется шифр: {cipher_name}.",
                    details=evidence["negotiated_cipher"],
                ))
            else:
                findings.append(TlsFinding(
                    label="Шифр",
                    status="info",
                    message="Шифр не удалось определить (диагностика).",
                ))

            # --- Диагностика цепочки ---
            chain_len = probe.get("chain_len")
            chain_subjects = probe.get("chain_subjects")
            if chain_len is None:
                secondary_notes.append({
                    "type": "diagnostic",
                    "message": "Цепочка сертификатов недоступна в текущем окружении (runtime limitation).",
                })
            else:
                secondary_notes.append({
                    "type": "diagnostic",
                    "message": f"Длина verified chain: {chain_len}.",
                    "details": {"subjects": chain_subjects},
                })

            # --- Поддержка TLS версий (best-effort) ---
            versions = await asyncio.to_thread(_probe_tls_versions)
            evidence["tls_versions_supported"] = versions

            # Классификация: если поддерживаются TLSv1.0/1.1 — warning
            legacy_supported = []
            if versions.get("TLSv1.0"):
                legacy_supported.append("TLSv1.0")
            if versions.get("TLSv1.1"):
                legacy_supported.append("TLSv1.1")

            if legacy_supported:
                findings.append(TlsFinding(
                    label="Поддержка устаревших TLS",
                    status="warning",
                    message=f"Сервер принимает устаревшие версии: {', '.join(legacy_supported)}.",
                    details={"supported": versions},
                ))
            else:
                # Для ok важно, чтобы был хотя бы TLS 1.2
                if versions.get("TLSv1.2") or versions.get("TLSv1.3"):
                    findings.append(TlsFinding(
                        label="Версии TLS",
                        status="ok",
                        message="Поддерживаются современные версии TLS (1.2+).",
                        details={"supported": versions},
                    ))
                else:
                    findings.append(TlsFinding(
                        label="Версии TLS",
                        status="critical",
                        message="Не обнаружена поддержка TLS 1.2/1.3 (возможна ошибка/ограничение проверки).",
                        details={"supported": versions},
                    ))

            # --- HSTS (best-effort) ---
            hsts = await asyncio.to_thread(_fetch_hsts)
            evidence["hsts"] = hsts

            hsts_header = (hsts.get("hsts") or "").strip()
            final_url = hsts.get("final_url")
            visited = hsts.get("visited") or []
            visited_schemes = [urlparse(u).scheme for u in visited if u]

            if "http" in visited_schemes:
                findings.append(TlsFinding(
                    label="Редиректы",
                    status="warning",
                    message="Обнаружен переход через http в цепочке редиректов.",
                    details={"visited": visited},
                ))

            if hsts_header:
                findings.append(TlsFinding(
                    label="HSTS",
                    status="ok",
                    message="HSTS заголовок присутствует.",
                    details={"strict-transport-security": hsts_header, "final_url": final_url},
                ))
            else:
                findings.append(TlsFinding(
                    label="HSTS",
                    status="warning",
                    message="HSTS не обнаружен (рекомендуется включить).",
                    details={"final_url": final_url, "status_code": hsts.get("status_code")},
                ))

            # --- Финализация ---
            score = _score_from_findings(findings)
            overall = _overall_status(findings)
            summary_text = _make_summary(findings, days_left_val)

            evidence["report"] = {
                "summary": {"status": overall, "score": score, "short": summary_text},
                "findings": [self._finding_to_dict(f) for f in findings],
                "secondary_notes": secondary_notes,
            }

            row = CheckRow(
                status="yes" if overall in ("ok", "warning") else "no",
                score=score,
                evidence_json=json.dumps(evidence, ensure_ascii=False),
            )

            module_payload = [{
                "checked_ts": int(time.time()),
                "status": overall,  # ok|warning|critical|info
                "score": score,
                "not_after": evidence["certificate"].get("notAfter"),
                "days_left": days_left_val,
                "issuer": json.dumps(evidence["certificate"].get("issuer"), ensure_ascii=False),
                "tls_version": tls_version,
                "cipher": cipher_name,
                "tls_versions_supported": json.dumps(versions, ensure_ascii=False),
                "hsts": hsts_header or None,
                "report_json": json.dumps(evidence["report"], ensure_ascii=False),
                "evidence_json": json.dumps(evidence, ensure_ascii=False),
            }]

            logger.info(
                "[tls] завершено: domain=%s overall=%s score=%s days_left=%s tls=%s cipher=%s",
                domain, overall, score, days_left_val, tls_version, cipher_name,
            )

        except (ssl.SSLError, socket.error, TimeoutError) as exc:
            logger.warning("[tls] ошибка проверки domain=%s: %s", domain, exc)

            # При ошибке: делаем отчёт максимально понятным
            findings = [
                TlsFinding(label="TLS handshake", status="critical", message="Не удалось установить TLS соединение."),
            ]
            score = _score_from_findings(findings)
            overall = _overall_status(findings)

            evidence["error"] = str(exc)
            evidence["report"] = {
                "summary": {"status": overall, "score": score, "short": "TLS недоступен или некорректно настроен."},
                "findings": [self._finding_to_dict(f) for f in findings],
                "secondary_notes": [{"type": "diagnostic", "message": str(exc)}],
            }

            row = CheckRow(
                status="no",
                score=score,
                evidence_json=json.dumps(evidence, ensure_ascii=False),
            )

            module_payload = [{
                "checked_ts": int(time.time()),
                "status": overall,
                "score": score,
                "not_after": None,
                "days_left": None,
                "issuer": None,
                "tls_version": None,
                "cipher": None,
                "tls_versions_supported": None,
                "hsts": None,
                "report_json": json.dumps(evidence["report"], ensure_ascii=False),
                "evidence_json": json.dumps(evidence, ensure_ascii=False),
            }]

        return ModuleResult(
            check_updates=[
                CheckUpdate(
                    key=self.key,
                    description="Проверка TLS и сертификата",
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
            logger.debug("[tls] persist: пустой payload domain=%s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[tls] persist: домен %s отсутствовал, создаём запись", domain)
            domain_record = create_domain(session, domain, source="audit")

        for item in payload:
            session.add(
                TlsCertificateCheck(
                    domain_id=domain_record.id,
                    checked_ts=_safe_int(item.get("checked_ts"), int(time.time())),
                    status=item.get("status", "critical"),
                    score=_safe_int(item.get("score"), 0),
                    not_after=item.get("not_after"),
                    days_left=item.get("days_left"),
                    issuer=item.get("issuer"),
                    tls_version=item.get("tls_version"),
                    cipher=item.get("cipher"),
                    tls_versions_supported=item.get("tls_versions_supported"),
                    hsts=item.get("hsts"),
                    report_json=item.get("report_json"),
                    evidence_json=item.get("evidence_json"),
                )
            )
        session.commit()
        logger.info("[tls] persist: сохранено domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        """
        Формирует блок отчёта по TLS, показывая последние 5 проверок.
        Новый формат:
          - summary (последний запуск)
          - entries (последние 5, компактно)
          - sections (из report_json последнего запуска, если есть)
          - secondary_notes (диагностика)
        """
        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "summary": None,
                "sections": [],
                "secondary_notes": [],
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

        if not rows:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "summary": None,
                "sections": [],
                "secondary_notes": [],
                "entries": [],
                "empty_message": "Проверки TLS ещё не выполнялись.",
            }

        # Последний запуск: берём report_json, если есть
        latest = rows[0]
        report = {}
        try:
            report = json.loads(latest.report_json or "{}")
        except Exception:
            report = {}

        summary = report.get("summary") or {
            "status": latest.status,
            "score": latest.score,
            "short": self._fallback_summary(latest),
        }

        # Sections: приводим findings к удобному виду
        findings = report.get("findings") or []
        secondary_notes = report.get("secondary_notes") or []

        sections = self._build_sections_from_findings(findings)

        # История (entries)
        entries = []
        for r in rows:
            ts = datetime.fromtimestamp(r.checked_ts).strftime("%d.%m.%Y %H:%M:%S")
            msg = self._fallback_summary(r)
            entries.append({
                "timestamp": ts,
                "status": r.status,
                "score": r.score,
                "message": msg,
                "details": {
                    "tls_version": r.tls_version,
                    "cipher": r.cipher,
                    "days_left": r.days_left,
                },
            })

        return {
            "key": self.key,
            "template": "audit_modules/tls_certificate/tls_certificate.html",
            "name": self.name,
            "description": self.description,
            "summary": summary,
            "sections": sections,
            "secondary_notes": secondary_notes,
            "entries": entries,
            "empty_message": "",
        }

    # ----------------------------
    # Внутренние helpers
    # ----------------------------

    @staticmethod
    def _finding_to_dict(f: TlsFinding) -> dict:
        return {
            "label": f.label,
            "status": f.status,
            "message": f.message,
            "details": f.details or {},
        }

    @staticmethod
    def _build_sections_from_findings(findings: list[dict]) -> list[dict]:
        """
        Группируем в интуитивные разделы.
        """
        cert_labels = {"Срок действия"}
        crypto_labels = {"Negotiated TLS", "Поддержка устаревших TLS", "Версии TLS", "Шифр"}
        http_labels = {"HSTS", "Редиректы"}

        sections_map = {
            "Сертификат": [],
            "Протоколы и шифры": [],
            "HTTP-защита": [],
            "Прочее": [],
        }

        for f in findings:
            label = (f.get("label") or "").strip()
            if label in cert_labels:
                sections_map["Сертификат"].append(f)
            elif label in crypto_labels:
                sections_map["Протоколы и шифры"].append(f)
            elif label in http_labels:
                sections_map["HTTP-защита"].append(f)
            else:
                sections_map["Прочее"].append(f)

        sections = []
        for title in ("Сертификат", "Протоколы и шифры", "HTTP-защита", "Прочее"):
            checks = sections_map[title]
            if checks:
                sections.append({"title": title, "checks": checks})
        return sections

    @staticmethod
    def _fallback_summary(row: "TlsCertificateCheck") -> str:
        """
        Компактная строка на случай, если report_json отсутствует/битый.
        """
        if row.status == "critical":
            base = "Критическая проблема TLS/сертификата."
        elif row.status == "warning":
            base = "Есть риск/рекомендации по TLS."
        elif row.status == "ok":
            base = "TLS настроен корректно."
        else:
            base = "Диагностика TLS."

        if row.days_left is not None:
            if row.days_left < 0:
                return f"{base} Сертификат истёк {abs(row.days_left)} дн. назад."
            return f"{base} До истечения: {row.days_left} дн."
        return base


# ----------------------------
# SQLAlchemy модель
# ----------------------------

class TlsCertificateCheck(Base):
    """Таблица результатов проверки TLS сертификата (расширенная)."""

    __tablename__ = "tls_certificate_checks"

    id = Column(Integer, primary_key=True)

    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    checked_ts = Column(Integer, nullable=False)

    # Новый статус: ok|warning|critical|info
    status = Column(String(32), nullable=False)

    # Баллы 0..100
    score = Column(Integer, nullable=False, default=0)

    # Сертификат/метаданные
    not_after = Column(String(128), nullable=True)
    days_left = Column(Integer, nullable=True)
    issuer = Column(Text, nullable=True)

    # TLS/crypto
    tls_version = Column(String(32), nullable=True)
    cipher = Column(String(128), nullable=True)
    tls_versions_supported = Column(Text, nullable=True)  # JSON

    # HTTP security
    hsts = Column(Text, nullable=True)

    # Готовый «читаемый» отчёт (JSON) и полный evidence (JSON)
    report_json = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=True)


# ----------------------------
# Нормализация сертификата
# ----------------------------

def _normalize_cert(cert: dict) -> dict:
    """Нормализует данные сертификата для сохранения в JSON (совместимо с твоей версией)."""

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
            dt = _parse_cert_time(value)
            normalized[field] = dt.isoformat() if dt else value
        else:
            normalized[field] = None

    return normalized
