from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from urllib.parse import urlunparse

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AdminPanelUpdate, AuditContext, ModuleResult
from src.webapp_db import AdminPanelRow, Base, Domain, create_domain

logger = logging.getLogger(__name__)


def _ensure_url(scheme: str, domain: str, path: str) -> str:
    """Собираем URL без query/fragment (единый формат для отчёта и доказательств)."""
    return urlunparse((scheme, domain, path, "", "", ""))


# Кандидаты путей админок.
# Дальше это будет расширяться и превращаться в сигнатурный движок (path + body/header hints).
ADMIN_PATH_CANDIDATES: list[dict[str, str]] = [
    {"key": "bitrix", "path": "/bitrix/admin/", "label": "Bitrix admin"},
    {"key": "wordpress", "path": "/wp-admin/", "label": "WordPress admin"},
    {"key": "joomla", "path": "/administrator/", "label": "Joomla admin"},
    {"key": "drupal", "path": "/user/login", "label": "Drupal login"},
    {"key": "opencart", "path": "/admin/", "label": "OpenCart / generic admin"},
    {"key": "generic", "path": "/admin", "label": "Generic admin"},
    {"key": "generic", "path": "/login", "label": "Generic login"},
]


def _is_admin_candidate_status(http_status: int | None) -> bool:
    """
    Какие коды считаем «похоже на админку/логин»:
    - 200: страница существует
    - 301/302: редирект на логин/канонический URL
    - 401/403: доступ ограничен (часто признак панели)
    """
    return http_status in (200, 301, 302, 401, 403)


class AdminDetectModule:
    """
    Универсальный модуль детекта административных панелей.

    Важно:
    - это НЕ «поиск уязвимостей», только инвентаризация потенциальных входов;
    - сигнатуры пока простые (по путям + HTTP-кодам), дальше нарастим контентные признаки.
    """

    key = "admin_detect"
    name = "Детект админок"
    description = "Проверяет популярные пути админок/логинов (Bitrix, WP, Joomla и др.)."
    depends_on: tuple[str, ...] = ("availability",)

    async def run(self, context: AuditContext) -> ModuleResult:
        availability = context.data.get("availability", {})
        if not availability or not availability.get("reachable"):
            logger.info("[admin_detect] skip: domain unreachable: %s", context.domain)
            return ModuleResult()

        scheme = availability.get("used_scheme") or "https"

        # Мы сохраняем один агрегированный результат в AdminPanelRow,
        # а детализацию/историю — в отдельной таблице admin_detect_checks.
        evidence: dict = {"domain": context.domain, "checked": {}, "hits": []}
        payload: list[dict] = []

        found_any = False
        best_hit: dict | None = None

        for item in ADMIN_PATH_CANDIDATES:
            url = _ensure_url(scheme, context.domain, item["path"])
            logger.debug("[admin_detect] check: %s", url)

            resp = await context.http.fetch(context.session, url, allow_redirects=False)

            if resp is None:
                evidence["checked"][item["path"]] = {"ok": False, "error": "unreachable"}
                payload.append(
                    {
                        "checked_ts": int(time.time()),
                        "panel_key": item["key"],
                        "path": item["path"],
                        "status": "no",
                        "http_status": None,
                        "final_url": None,
                        "evidence_json": json.dumps({"url": url, "error": "unreachable"}, ensure_ascii=False),
                    }
                )
                continue

            hit = {
                "panel_key": item["key"],
                "path": item["path"],
                "label": item["label"],
                "http_status": resp.status,
                "final_url": resp.final_url,
            }
            evidence["checked"][item["path"]] = {"ok": True, "status": resp.status, "final_url": resp.final_url}

            is_candidate = _is_admin_candidate_status(resp.status)
            payload.append(
                {
                    "checked_ts": int(time.time()),
                    "panel_key": item["key"],
                    "path": item["path"],
                    "status": "yes" if is_candidate else "no",
                    "http_status": resp.status,
                    "final_url": resp.final_url,
                    "evidence_json": json.dumps(hit, ensure_ascii=False),
                }
            )

            if is_candidate:
                found_any = True
                evidence["hits"].append(hit)
                # best_hit = первый найденный «похожий», либо можно будет сделать приоритезацию
                if best_hit is None:
                    best_hit = hit

        # Единый итоговый статус (для UI и общей таблицы админок)
        admin_status = "yes" if found_any else "no"

        admin_row = AdminPanelRow(
            status=admin_status,
            http_status=(best_hit or {}).get("http_status"),
            final_url=(best_hit or {}).get("final_url"),
            evidence_json=json.dumps(evidence, ensure_ascii=False),
        )

        logger.info(
            "[admin_detect] domain=%s status=%s hits=%s",
            context.domain,
            admin_status,
            len(evidence.get("hits", [])),
        )

        return ModuleResult(
            admin_updates=[AdminPanelUpdate(panel_key="admin_detect", row=admin_row)],
            module_payload=payload,
        )

    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        """Сохраняет историю проверок админок в таблицу admin_detect_checks."""
        if not payload:
            logger.debug("[admin_detect] persist: no payload for %s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[admin_detect] persist: create domain=%s before save", domain)
            domain_record = create_domain(session, domain, source="audit")

        for item in payload:
            session.add(
                AdminDetectCheck(
                    domain_id=domain_record.id,
                    checked_ts=item.get("checked_ts", int(time.time())),
                    panel_key=item.get("panel_key", "generic"),
                    path=item.get("path", ""),
                    status=item.get("status", "no"),
                    http_status=item.get("http_status"),
                    final_url=item.get("final_url"),
                    evidence_json=item.get("evidence_json"),
                )
            )

        session.commit()
        logger.info("[admin_detect] persist: saved domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        """Блок отчёта: показываем последние 10 проверок (путь + код)."""
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
            session.query(AdminDetectCheck)
            .filter(AdminDetectCheck.domain_id == domain_record.id)
            .order_by(AdminDetectCheck.checked_ts.desc())
            .limit(10)
            .all()
        )

        entries = []
        for row in rows:
            timestamp = datetime.fromtimestamp(row.checked_ts).strftime("%d.%m.%Y %H:%M:%S")
            if row.http_status is None:
                message = f"{row.path}: нет ответа"
            else:
                message = f"{row.path}: HTTP {row.http_status}"
            entries.append(
                {
                    "timestamp": timestamp,
                    "status": row.status,
                    "message": message,
                    "details": {"panel_key": row.panel_key, "path": row.path, "final_url": row.final_url},
                }
            )

        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "entries": entries,
            "empty_message": "Проверки админок ещё не выполнялись.",
        }


class AdminDetectCheck(Base):
    """Таблица истории проверок админок (универсальная)."""

    __tablename__ = "admin_detect_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    checked_ts = Column(Integer, nullable=False)

    panel_key = Column(String(64), nullable=False)  # bitrix / wordpress / joomla / generic ...
    path = Column(String(255), nullable=False)

    status = Column(String(32), nullable=False)  # yes/no
    http_status = Column(Integer, nullable=True)
    final_url = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=True)
