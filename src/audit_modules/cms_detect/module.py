from __future__ import annotations

import json
import logging
import time
from datetime import datetime

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AuditContext, CheckUpdate, CmsUpdate, ModuleResult
from src.webapp_db import Base, CheckRow, CmsRow, Domain, create_domain

from .detectors import default_detectors
from .detectors.utils import decode_html

logger = logging.getLogger(__name__)


class CmsDetectModule:
    """
    Единый аудит определения CMS/фреймворков.
    Внутри вызывает набор детекторов, каждый отвечает только за свою CMS.
    """

    key = "cms_detect"
    name = "Определение CMS / фреймворка"
    description = "Определяет CMS/фреймворки по сигнатурам (headers/cookies/HTML)."
    depends_on: tuple[str, ...] = ("availability",)

    async def run(self, context: AuditContext) -> ModuleResult:
        availability = context.data.get("availability")
        checked_ts = int(time.time())

        # Готовим “пустой” результат заранее (единая точка выхода при проблемах).
        def _result(status: str, score: int, evidence: dict, *, cms_updates: list[CmsUpdate] | None = None) -> ModuleResult:
            row = CheckRow(status=status, score=score, evidence_json=json.dumps(evidence, ensure_ascii=False))
            mr = ModuleResult(
                check_updates=[CheckUpdate(key="cms", description="Определение CMS/фреймворка", row=row)],
                module_payload=[{"checked_ts": checked_ts, "status": status, "score": score, "evidence_json": row.evidence_json}],
            )
            if cms_updates:
                mr.cms_updates.extend(cms_updates)
            return mr

        # --- Gate: домен должен быть “жив” согласно availability
        if not availability or not availability.get("reachable"):
            logger.info("[cms_detect] skip: domain unreachable: %s", context.domain)
            evidence = {"domain": context.domain, "error": "unreachable"}
            context.data.setdefault("cms", {})["summary"] = {"status": "no", "confidence": 0, "detected": []}
            return _result("no", 0, evidence)

        homepage = availability.get("homepage")
        if homepage is None:
            logger.warning("[cms_detect] availability.homepage missing for %s", context.domain)
            evidence = {"domain": context.domain, "error": "availability_missing"}
            context.data.setdefault("cms", {})["summary"] = {"status": "no", "confidence": 0, "detected": []}
            return _result("no", 0, evidence)

        used_url = getattr(homepage, "final_url", None)
        headers = getattr(homepage, "headers", {}) or {}
        set_cookie_raw = availability.get("set_cookie", "") or ""
        html = decode_html(homepage.body, homepage.charset)

        detectors = default_detectors()
        logger.info("[cms_detect] start domain=%s detectors=%s", context.domain, [d.cms_key for d in detectors])

        # --- прогоняем детекторы
        results = []
        for det in detectors:
            try:
                r = det.detect(headers=headers, set_cookie_raw=set_cookie_raw, html=html, used_url=used_url)
                results.append(r)
                logger.debug("[cms_detect] det=%s status=%s score=%s signals=%s", r.cms_key, r.status, r.score, len(r.evidence.signals))
            except Exception as exc:
                # Ошибка одного детектора не должна ломать весь аудит
                logger.exception("[cms_detect] detector_failed det=%s domain=%s: %s", det.cms_key, context.domain, exc)

        # сортировка кандидатов
        results.sort(key=lambda x: x.score, reverse=True)
        top = results[:5]

        detected_yes = [r for r in results if r.status == "yes"]
        detected_maybe = [r for r in results if r.status == "maybe"]

        # Итоговый статус/скор: если есть хотя бы один yes — yes, иначе maybe если есть maybe, иначе no.
        if detected_yes:
            final_status = "yes"
            final_score = detected_yes[0].score
        elif detected_maybe:
            final_status = "maybe"
            final_score = detected_maybe[0].score
        else:
            final_status = "no"
            final_score = 0

        evidence = {
            "domain": context.domain,
            "used_url": used_url,
            "final": {"status": final_status, "score": final_score},
            "top_candidates": [
                {
                    "cms_key": r.cms_key,
                    "cms_name": r.cms_name,
                    "status": r.status,
                    "score": r.score,
                    "signals": r.evidence.signals,
                }
                for r in top
            ],
        }

        # В context складываем summary (может пригодиться другим модулям)
        context.data.setdefault("cms", {})["summary"] = {
            "status": final_status,
            "confidence": final_score,
            "detected": [{"cms_key": r.cms_key, "status": r.status, "confidence": r.score} for r in top],
        }

        # CmsUpdate — для каждого yes/maybe кандидата (на практике удобно сохранять и maybe).
        cms_updates: list[CmsUpdate] = []
        for r in results:
            if r.status in ("yes", "maybe"):
                cms_evidence = {
                    "domain": context.domain,
                    "used_url": used_url,
                    "signals": r.evidence.signals,
                    "score": r.score,
                }
                cms_updates.append(
                    CmsUpdate(
                        cms_key=r.cms_key,
                        cms_name=r.cms_name,
                        row=CmsRow(status=r.status, confidence=r.score, evidence_json=json.dumps(cms_evidence, ensure_ascii=False)),
                    )
                )

        logger.info(
            "[cms_detect] done domain=%s final_status=%s final_score=%s top=%s",
            context.domain,
            final_status,
            final_score,
            [(r.cms_key, r.score) for r in top],
        )

        return _result(final_status, final_score, evidence, cms_updates=cms_updates)

    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        """
        Сохраняет результат сводного cms_detect в таблицу cms_detect_checks.
        """
        if not payload:
            logger.debug("[cms_detect] persist: no payload for %s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[cms_detect] persist: create domain=%s before save", domain)
            domain_record = create_domain(session, domain, source="audit")

        for item in payload:
            session.add(
                CmsDetectCheck(
                    domain_id=domain_record.id,
                    checked_ts=item.get("checked_ts", int(time.time())),
                    status=item.get("status", "no"),
                    score=item.get("score", 0),
                    evidence_json=item.get("evidence_json"),
                )
            )

        session.commit()
        logger.info("[cms_detect] persist: saved domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        """
        Строит Report v2 + legacy entries.
        Показывает последние 5 запусков cms_detect и агрегирует “последний результат”.
        """
        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "headline": "Нет данных по домену",
                "kpis": [],
                "checks": {},
                "insights": [],
                "timeline": [],
                "entries": [],
                "empty_message": "Данные о домене отсутствуют в базе.",
            }

        rows = (
            session.query(CmsDetectCheck)
            .filter(CmsDetectCheck.domain_id == domain_record.id)
            .order_by(CmsDetectCheck.checked_ts.desc())
            .limit(5)
            .all()
        )

        if not rows:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "headline": "Определение CMS ещё не выполнялось",
                "kpis": [],
                "checks": {},
                "insights": [],
                "timeline": [],
                "entries": [],
                "empty_message": "Проверки CMS/фреймворков ещё не выполнялись.",
            }

        # Последняя запись — основа “красивого” отчёта.
        latest = rows[0]
        latest_ev = {}
        try:
            latest_ev = json.loads(latest.evidence_json or "{}")
        except Exception:
            latest_ev = {}

        final = (latest_ev.get("final") or {})
        top = latest_ev.get("top_candidates") or []

        # Report v2 headline
        if latest.status == "yes":
            headline = "CMS/фреймворк определён"
        elif latest.status == "maybe":
            headline = "Обнаружены кандидаты, уверенность средняя"
        else:
            headline = "CMS/фреймворк не определён по сигнатурам"

        # KPI
        kpis = {
            "status": latest.status,
            "confidence": latest.score,
            "used_url": latest_ev.get("used_url"),
        }

        # Insights (человеческие выводы)
        insights: list[str] = []
        if top:
            best = top[0]
            insights.append(f"Основной кандидат: {best.get('cms_name')} (score={best.get('score')}).")
            if len(top) > 1:
                insights.append("Дополнительные кандидаты присутствуют — проверьте сигналы, если нужна точность.")
        else:
            insights.append("Сигнатуры CMS не найдены в headers/cookies/HTML главной страницы.")

        # Timeline (упрощённо: последние 5 запусков)
        timeline = []
        for r in rows:
            ts = datetime.fromtimestamp(r.checked_ts).strftime("%d.%m.%Y %H:%M:%S")
            timeline.append({"timestamp": ts, "status": r.status, "title": f"cms_detect: {r.status} (score={r.score})", "meta": {}})

        # Legacy entries
        entries = []
        for r in rows:
            ts = datetime.fromtimestamp(r.checked_ts).strftime("%d.%m.%Y %H:%M:%S")
            entries.append({"timestamp": ts, "status": r.status, "message": f"статус={r.status}, score={r.score}", "details": {}})

        # Checks (что использовали)
        checks = {
            "source": "availability.homepage",
            "signals": ["headers", "set-cookie", "html"],
            "top_candidates_count": len(top),
            "used_url": latest_ev.get("used_url"),
        }

        # Важно: возвращаем и top_candidates в явном виде — UI сможет красиво отрисовать.
        return {
            "key": self.key,
            "template": "audit_modules/cms_detect/cms_detect.html",
            "name": self.name,
            "description": self.description,
            "headline": headline,
            "kpis": kpis,
            "checks": checks,
            "insights": insights,
            "timeline": timeline,
            "top_candidates": top,
            "entries": entries,
            "empty_message": "—",
        }


class CmsDetectCheck(Base):
    """
    История сводного определения CMS/фреймворка.
    evidence_json хранит топ кандидатов + сигналы.
    """

    __tablename__ = "cms_detect_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)

    checked_ts = Column(Integer, nullable=False)
    status = Column(String(32), nullable=False)
    score = Column(Integer, nullable=False, default=0)

    evidence_json = Column(Text, nullable=True)
