from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AuditContext, CheckUpdate, ModuleResult
from src.webapp_db import Base, CheckRow, Domain, create_domain

logger = logging.getLogger(__name__)

# Публичные резолверы для сравнения (эвристика split-horizon).
PUBLIC_RESOLVERS: tuple[tuple[str, list[str]], ...] = (
    ("system", []),  # системный резолвер (как настроено в ОС/контейнере)
    ("cloudflare", ["1.1.1.1", "1.0.0.1"]),
    ("google", ["8.8.8.8", "8.8.4.4"]),
)

# Типы записей, которые собираем в MVP.
RR_TYPES: tuple[str, ...] = ("A", "AAAA", "CNAME", "NS", "SOA", "CAA", "DS", "DNSKEY", "RRSIG")


def _safe_json(obj: Any) -> str:
    """Безопасная сериализация под evidence/payload (без падений на неожиданных типах)."""
    return json.dumps(obj, ensure_ascii=False, default=str)


def _now_ts() -> int:
    return int(time.time())


@dataclass(frozen=True)
class RrQueryResult:
    ok: bool
    rrtype: str
    answers: list[dict]  # структурированный список ответов
    ttl: int | None  # ttl rrset (если есть)
    error: str | None  # текст ошибки (если есть)


class DnsAuditModule:
    key = "dns"
    name = "DNS-аудит"
    description = "Собирает DNS-записи (A/AAAA/CNAME, NS/SOA, TTL), CAA, признаки split-horizon и DNSSEC."
    depends_on: tuple[str, ...] = ()

    # Таймауты и ретраи — достаточно консервативные, чтобы не «убивать» сеть в массовом аудите.
    DNS_TIMEOUT_S = 2.5
    DNS_LIFETIME_S = 4.0
    RETRIES = 2

    async def run(self, context: AuditContext) -> ModuleResult:
        """
        DNS — синхронные запросы (через dnspython). Запускаем их в рамках общего воркера;
        при необходимости позже вынесем в threadpool. Для MVP оставляем просто и прозрачно.
        """
        domain = context.domain
        checked_ts = _now_ts()

        logger.info("[dns] start domain=%s ts=%s", domain, checked_ts)

        # --- Пытаемся импортировать dnspython. Без неё модуль вежливо пропускается.
        try:
            import dns.resolver  # type: ignore
            import dns.flags  # type: ignore
        except Exception as e:
            logger.warning("[dns] dnspython missing -> skip domain=%s err=%s", domain, e)
            evidence = {
                "domain": domain,
                "checked_ts": checked_ts,
                "skipped": True,
                "reason": "dnspython_not_installed",
            }
            return ModuleResult(
                check_updates=[
                    CheckUpdate(
                        key=self.key,
                        description="DNS-аудит пропущен (dnspython не установлен)",
                        row=CheckRow(status="no", score=0, evidence_json=_safe_json(evidence)),
                    )
                ],
                module_payload=[
                    {
                        "checked_ts": checked_ts,
                        "resolver_name": "system",
                        "rrtype": "META",
                        "ok": False,
                        "ttl": None,
                        "answers_json": None,
                        "error": "dnspython_not_installed",
                        "evidence_json": _safe_json(evidence),
                    }
                ],
            )

        def make_resolver(nameservers: list[str]):
            """
            Конструируем резолвер:
            - если nameservers пустой список -> используем системный конфиг
            - иначе -> указываем явные NS (Cloudflare/Google)
            """
            r = dns.resolver.Resolver(configure=(len(nameservers) == 0))
            if nameservers:
                r.nameservers = nameservers
            r.timeout = self.DNS_TIMEOUT_S
            r.lifetime = self.DNS_LIFETIME_S
            # Важно: не включаем агрессивные настройки; аудит должен быть предсказуемым.
            return r

        def query_rr(resolver_name: str, resolver, qname: str, rrtype: str) -> RrQueryResult:
            """
            Выполняет DNS-запрос с ретраями и возвращает нормализованный результат.
            Для DNSSEC используем флаг want_dnssec, чтобы получить RRSIG/DNSKEY там, где возможно.
            """
            last_err: str | None = None

            for attempt in range(1, self.RETRIES + 1):
                logger.info(
                    "[dns] query domain=%s resolver=%s rrtype=%s attempt=%s/%s",
                    domain,
                    resolver_name,
                    rrtype,
                    attempt,
                    self.RETRIES,
                )
                try:
                    try:
                        # Новые версии dnspython поддерживают want_dnssec
                        ans = resolver.resolve(
                            qname,
                            rrtype,
                            raise_on_no_answer=False,
                            search=True,
                            want_dnssec=True,
                        )
                    except TypeError:
                        # Старые версии dnspython: параметра want_dnssec нет
                        logger.info(
                            "[dns] want_dnssec unsupported -> fallback domain=%s resolver=%s rrtype=%s",
                            domain,
                            resolver_name,
                            rrtype,
                        )
                        ans = resolver.resolve(
                            qname,
                            rrtype,
                            raise_on_no_answer=False,
                            search=True,
                        )

                    ttl = getattr(ans.rrset, "ttl", None) if getattr(ans, "rrset", None) is not None else None
                    answers: list[dict] = []

                    if ans.rrset is not None:
                        for item in ans:
                            # Нормализация значений в JSON-friendly структуру.
                            answers.append({"text": item.to_text()})

                    logger.info(
                        "[dns] ok domain=%s resolver=%s rrtype=%s ttl=%s answers=%s",
                        domain,
                        resolver_name,
                        rrtype,
                        ttl,
                        len(answers),
                    )
                    return RrQueryResult(ok=True, rrtype=rrtype, answers=answers, ttl=ttl, error=None)

                except Exception as e:
                    last_err = str(e)
                    logger.warning(
                        "[dns] fail domain=%s resolver=%s rrtype=%s attempt=%s/%s err=%s",
                        domain,
                        resolver_name,
                        rrtype,
                        attempt,
                        self.RETRIES,
                        last_err,
                    )

            return RrQueryResult(ok=False, rrtype=rrtype, answers=[], ttl=None, error=last_err or "unknown_error")

        # --- Основной сбор фактов ---
        evidence: dict[str, Any] = {
            "domain": domain,
            "checked_ts": checked_ts,
            "resolvers": {},
            "derived": {},
        }

        payload: list[dict] = []

        # Для split-horizon будем сравнивать ответы A/AAAA/NS между резолверами.
        compare_matrix: dict[str, dict[str, set[str]]] = {
            "A": {},
            "AAAA": {},
            "NS": {},
        }

        for resolver_name, ns_list in PUBLIC_RESOLVERS:
            resolver = make_resolver(ns_list)

            resolver_block: dict[str, Any] = {"nameservers": ns_list, "records": {}}
            evidence["resolvers"][resolver_name] = resolver_block

            for rrtype in RR_TYPES:
                res = query_rr(resolver_name, resolver, domain, rrtype)

                resolver_block["records"][rrtype] = {
                    "ok": res.ok,
                    "ttl": res.ttl,
                    "answers": res.answers,
                    "error": res.error,
                }

                payload.append(
                    {
                        "checked_ts": checked_ts,
                        "resolver_name": resolver_name,
                        "rrtype": rrtype,
                        "ok": True if res.ok else False,
                        "ttl": res.ttl,
                        "answers_json": _safe_json(res.answers) if res.answers else None,
                        "error": res.error,
                        "evidence_json": None,  # заполним единым evidence_json ниже
                    }
                )

                # Готовим структуру для сравнения (split-horizon).
                if rrtype in compare_matrix:
                    vals = {a.get("text", "") for a in res.answers if a.get("text")}
                    compare_matrix[rrtype][resolver_name] = vals

        # --- Производные выводы (split-horizon / dnssec / caa) ---

        # split-horizon (эвристика):
        # если системный резолвер и публичные дают заметно разные множества A/AAAA/NS — подозрение.
        split_horizon_signals: list[str] = []
        for rrtype in ("A", "AAAA", "NS"):
            base = compare_matrix[rrtype].get("system", set())
            for other_name in ("cloudflare", "google"):
                other = compare_matrix[rrtype].get(other_name, set())
                if base and other and base != other:
                    split_horizon_signals.append(f"{rrtype}: system != {other_name}")

        split_horizon_suspected = len(split_horizon_signals) > 0

        # DNSSEC (эвристика, без криптовалидации):
        # - наличие DNSKEY (в зоне) и/или DS (в родительской, если резолвер возвращает)
        # - наличие RRSIG на DNSKEY/записях
        sys_records = evidence["resolvers"].get("system", {}).get("records", {})
        dnskey_ok = bool(sys_records.get("DNSKEY", {}).get("ok")) and bool(sys_records.get("DNSKEY", {}).get("answers"))
        ds_ok = bool(sys_records.get("DS", {}).get("ok")) and bool(sys_records.get("DS", {}).get("answers"))
        rrsig_ok = bool(sys_records.get("RRSIG", {}).get("ok")) and bool(sys_records.get("RRSIG", {}).get("answers"))
        dnssec_present = bool(dnskey_ok or ds_ok or rrsig_ok)

        # CAA
        caa_present = bool(sys_records.get("CAA", {}).get("ok")) and bool(sys_records.get("CAA", {}).get("answers"))

        # TTL KPI (берём минимальный TTL из ключевых типов, по system)
        ttl_candidates: list[int] = []
        for rrtype in ("A", "AAAA", "CNAME", "NS"):
            ttl = sys_records.get(rrtype, {}).get("ttl")
            if isinstance(ttl, int):
                ttl_candidates.append(ttl)
        ttl_min = min(ttl_candidates) if ttl_candidates else None

        evidence["derived"] = {
            "split_horizon_suspected": split_horizon_suspected,
            "split_horizon_signals": split_horizon_signals,
            "dnssec_present": dnssec_present,
            "dnssec_signals": {
                "dnskey_ok": dnskey_ok,
                "ds_ok": ds_ok,
                "rrsig_ok": rrsig_ok,
            },
            "caa_present": caa_present,
            "ttl_min": ttl_min,
        }

        evidence_json = _safe_json(evidence)
        for item in payload:
            item["evidence_json"] = evidence_json

        # --- Скоринг и итоговый статус ---
        # Простой практичный скор:
        # +20 если есть CAA
        # +20 если есть DNSSEC признаки
        # -10 если подозрение split-horizon (не всегда плохо, но требует внимания)
        # База: 60 при успешных ответах хотя бы на A/AAAA/NS (system).
        sys_a_ok = bool(sys_records.get("A", {}).get("ok"))
        sys_aaaa_ok = bool(sys_records.get("AAAA", {}).get("ok"))
        sys_ns_ok = bool(sys_records.get("NS", {}).get("ok"))
        base_ok = sys_a_ok or sys_aaaa_ok or sys_ns_ok

        score = 0
        status = "no"
        if base_ok:
            status = "yes"
            score = 60
            if caa_present:
                score += 20
            if dnssec_present:
                score += 20
            if split_horizon_suspected:
                score = max(0, score - 10)
            score = min(100, score)

        # Сохраним в контекст (может пригодиться дальше)
        context.data["dns"] = evidence["derived"]

        logger.info(
            "[dns] done domain=%s status=%s score=%s split_horizon=%s dnssec=%s caa=%s ttl_min=%s",
            domain,
            status,
            score,
            split_horizon_suspected,
            dnssec_present,
            caa_present,
            ttl_min,
        )

        return ModuleResult(
            check_updates=[
                CheckUpdate(
                    key=self.key,
                    description="DNS-аудит: записи, TTL, CAA, DNSSEC и split-horizon эвристика",
                    row=CheckRow(status=status, score=score, evidence_json=evidence_json),
                )
            ],
            module_payload=payload,
        )

    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        """Сохраняет сырые результаты DNS в таблицу dns_checks."""
        if not payload:
            logger.debug("[dns] no payload -> skip persist domain=%s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[dns] domain missing -> create domain=%s", domain)
            domain_record = create_domain(session, domain, source="audit")

        for item in payload:
            session.add(
                DnsCheck(
                    domain_id=domain_record.id,
                    checked_ts=item.get("checked_ts", _now_ts()),
                    resolver_name=item.get("resolver_name"),
                    rrtype=item.get("rrtype"),
                    ok="yes" if item.get("ok") else "no",
                    ttl=item.get("ttl"),
                    answers_json=item.get("answers_json"),
                    error=item.get("error"),
                    evidence_json=item.get("evidence_json"),
                )
            )

        session.commit()
        logger.info("[dns] persisted domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        """
        Report v2 + legacy entries.
        - v2: headline/kpis/checks/insights/timeline
        - legacy: entries (последние N записей)
        """
        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "entries": [],
                "empty_message": "Данные о домене отсутствуют в базе.",
                "headline": "Данные отсутствуют",
                "kpis": {},
                "insights": [],
                "checks": {"resolvers": [n for n, _ in PUBLIC_RESOLVERS], "rr_types": list(RR_TYPES)},
                "timeline": [],
            }

        # Берём последнюю "пачку" по checked_ts (один запуск = один timestamp).
        last_ts = (
            session.query(DnsCheck.checked_ts)
            .filter(DnsCheck.domain_id == domain_record.id)
            .order_by(DnsCheck.checked_ts.desc())
            .limit(1)
            .scalar()
        )
        if last_ts is None:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "entries": [],
                "empty_message": "Нет записей DNS-аудита для домена.",
                "headline": "Нет данных DNS-аудита",
                "kpis": {},
                "insights": [],
                "checks": {"resolvers": [n for n, _ in PUBLIC_RESOLVERS], "rr_types": list(RR_TYPES)},
                "timeline": [],
            }

        rows = (
            session.query(DnsCheck)
            .filter(DnsCheck.domain_id == domain_record.id)
            .filter(DnsCheck.checked_ts == last_ts)
            .order_by(DnsCheck.resolver_name.asc(), DnsCheck.rrtype.asc())
            .all()
        )

        # Попробуем поднять evidence_json из любой строки (оно одинаковое для пачки).
        evidence = {}
        for r in rows:
            if r.evidence_json:
                try:
                    evidence = json.loads(r.evidence_json)
                except Exception:
                    evidence = {}
                break

        derived = (evidence.get("derived") or {}) if isinstance(evidence, dict) else {}
        split_horizon = bool(derived.get("split_horizon_suspected"))
        dnssec_present = bool(derived.get("dnssec_present"))
        caa_present = bool(derived.get("caa_present"))
        ttl_min = derived.get("ttl_min")

        # KPI
        # Для удобства UI подсчитаем кол-ва A/AAAA/NS по system.
        def _answers_count(resolver_name: str, rrtype: str) -> int:
            for r in rows:
                if r.resolver_name == resolver_name and r.rrtype == rrtype and r.answers_json:
                    try:
                        arr = json.loads(r.answers_json)
                        return len(arr) if isinstance(arr, list) else 0
                    except Exception:
                        return 0
            return 0

        kpis = {
            "ttl_min": ttl_min,
            "dnssec_present": "yes" if dnssec_present else "no",
            "caa_present": "yes" if caa_present else "no",
            "split_horizon_suspected": "yes" if split_horizon else "no",
            "a_count": _answers_count("system", "A"),
            "aaaa_count": _answers_count("system", "AAAA"),
            "ns_count": _answers_count("system", "NS"),
        }

        # Headline
        if not rows:
            headline = "Нет данных DNS-аудита"
        else:
            headline = "DNS-снимок собран"
            if split_horizon:
                headline = "DNS: возможен split-horizon"
            elif dnssec_present and caa_present:
                headline = "DNS: обнаружены DNSSEC и CAA"
            elif dnssec_present:
                headline = "DNS: обнаружены признаки DNSSEC"
            elif caa_present:
                headline = "DNS: обнаружены записи CAA"

        # Insights
        insights: list[str] = []
        if split_horizon:
            sig = derived.get("split_horizon_signals") or []
            insights.append(
                f"Обнаружены различия ответов между резолверами: {', '.join(sig) if sig else 'есть расхождения.'}")
        else:
            insights.append(
                "Существенных расхождений между системным и публичными резолверами не выявлено (эвристика).")

        if dnssec_present:
            insights.append("Присутствуют признаки DNSSEC (DNSKEY/DS/RRSIG).")
        else:
            insights.append("Признаки DNSSEC не обнаружены (это не всегда проблема, но снижает защиту зоны).")

        if caa_present:
            insights.append(
                "Найдены записи CAA — это помогает ограничивать, какие УЦ могут выпускать сертификаты для домена.")
        else:
            insights.append("Записи CAA не найдены — домен не ограничивает выпуск сертификатов через CAA.")

        if isinstance(ttl_min, int):
            insights.append(f"Минимальный TTL по ключевым записям (system): {ttl_min} сек.")
        else:
            insights.append("TTL по ключевым записям определить не удалось (нет данных или ответы пусты).")

        # Timeline (упрощённо: один event на запуск)
        timeline = [
            {
                "timestamp": datetime.fromtimestamp(last_ts).strftime("%d.%m.%Y %H:%M:%S"),
                "status": "ok" if rows else "no_data",
                "title": "DNS-аудит выполнен",
                "meta": {
                    "resolvers": [n for n, _ in PUBLIC_RESOLVERS],
                    "rr_types": list(RR_TYPES),
                },
            }
        ]

        # Legacy entries (последние 30 строк по домену)
        last_rows = (
            session.query(DnsCheck)
            .filter(DnsCheck.domain_id == domain_record.id)
            .order_by(DnsCheck.checked_ts.desc())
            .limit(30)
            .all()
        )

        entries = []
        for r in last_rows:
            ts_str = datetime.fromtimestamp(r.checked_ts).strftime("%d.%m.%Y %H:%M:%S")
            msg = "OK" if r.ok == "yes" else "FAIL"
            details = {
                "resolver": r.resolver_name,
                "rrtype": r.rrtype,
                "ttl": r.ttl,
                "error": r.error,
            }
            entries.append(
                {"timestamp": ts_str, "status": msg, "message": f"{r.resolver_name} {r.rrtype}", "details": details})

        # === Matrix для шаблона: resolver x rrtype ===
        matrix: dict[str, dict[str, dict]] = {}
        for r in rows:
            matrix.setdefault(r.resolver_name, {})
            try:
                answers = json.loads(r.answers_json) if r.answers_json else []
                if not isinstance(answers, list):
                    answers = []
            except Exception:
                answers = []

            matrix[r.resolver_name][r.rrtype] = {
                "ok": (r.ok == "yes"),
                "ttl": r.ttl,
                "answers": answers,  # [{text: "..."}]
                "error": r.error,
            }

        return {
            "key": self.key,
            "template": "audit_modules/dns/dns.html",
            "name": self.name,
            "description": self.description,
            "headline": headline,
            "kpis": kpis,
            "checks": {"resolvers": [n for n, _ in PUBLIC_RESOLVERS], "rr_types": list(RR_TYPES),
                       "retries": self.RETRIES},
            "insights": insights,
            "timeline": timeline,
            "matrix": matrix,
            "entries": entries,
        }


class DnsCheck(Base):
    """
    Таблица сырых фактов DNS.
    Один запуск формирует пачку строк с единым checked_ts (для grouping).
    """
    __tablename__ = "dns_checks"

    id = Column(Integer, primary_key=True, autoincrement=True)

    domain_id = Column(Integer, ForeignKey("domains.id"), index=True, nullable=False)
    checked_ts = Column(Integer, index=True, nullable=False)

    resolver_name = Column(String(32), nullable=False)  # system/cloudflare/google
    rrtype = Column(String(16), nullable=False)  # A/AAAA/NS/...
    ok = Column(String(8), nullable=False)  # yes/no

    ttl = Column(Integer, nullable=True)
    answers_json = Column(Text, nullable=True)  # JSON(list[{text: "..."}])
    error = Column(Text, nullable=True)

    evidence_json = Column(Text, nullable=True)  # общий evidence для запуска (одинаковый во всех строках)
