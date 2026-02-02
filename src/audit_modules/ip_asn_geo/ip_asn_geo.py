from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AuditContext, CheckUpdate, ModuleResult
from src.webapp_db import Base, CheckRow, Domain, create_domain

logger = logging.getLogger(__name__)


def _safe_json(obj: Any) -> str:
    """Сериализация без падений на неожиданных типах."""
    return json.dumps(obj, ensure_ascii=False, default=str)


def _now_ts() -> int:
    return int(time.time())


# Известные “массовые” инфраструктуры (эвристика).
# В будущем можно расширять/вынести в конфиг.
MASS_INFRA_HINTS = (
    "cloudflare",
    "akamai",
    "fastly",
    "incapsula",
    "imperva",
    "google",
    "amazon",
    "aws",
    "microsoft",
    "azure",
    "digitalocean",
    "ovh",
    "hetzner",
)


@dataclass(frozen=True)
class IpEnrichment:
    ip: str
    version: int  # 4 or 6
    asn: str | None
    asn_description: str | None
    org: str | None
    country: str | None
    registry: str | None
    rdap_url: str | None
    error: str | None


class IpAsnGeoAuditModule:
    key = "ip_asn_geo"
    name = "IP/ASN/география"
    description = "Определяет IP, ASN, провайдера и страну/географию. Проверяет ротацию IP и признаки массовой инфраструктуры."
    depends_on: tuple[str, ...] = ("dns",)  # если dns-аудит уже есть — используем его данные; иначе fallback.

    # Таймауты на сетевые операции RDAP (через ipwhois) фактически зависят от внешних сервисов.
    # ipwhois не всегда идеально предсказуем по времени; поэтому выполняем в threadpool.
    LOOKUP_CONCURRENCY = 8

    async def run(self, context: AuditContext) -> ModuleResult:
        domain = context.domain
        checked_ts = _now_ts()

        logger.info("[ip_asn_geo] start domain=%s ts=%s", domain, checked_ts)

        # 1) Получаем IP адреса
        ips = self._collect_ips_from_context_or_dns(context)
        if not ips:
            # fallback на socket.getaddrinfo
            ips = self._collect_ips_socket(domain)

        ips_v4 = sorted({ip for ip in ips if ":" not in ip})
        ips_v6 = sorted({ip for ip in ips if ":" in ip})
        all_ips = ips_v4 + ips_v6

        logger.info(
            "[ip_asn_geo] resolved ips domain=%s v4=%s v6=%s total=%s",
            domain,
            len(ips_v4),
            len(ips_v6),
            len(all_ips),
        )

        if not all_ips:
            evidence = {
                "domain": domain,
                "checked_ts": checked_ts,
                "ips": [],
                "derived": {"rotation": "unknown"},
                "errors": ["no_ips_resolved"],
            }
            return ModuleResult(
                check_updates=[
                    CheckUpdate(
                        key=self.key,
                        description="IP/ASN/география: не удалось получить IP адреса",
                        row=CheckRow(status="no", score=0, evidence_json=_safe_json(evidence)),
                    )
                ],
                module_payload=[
                    {
                        "checked_ts": checked_ts,
                        "ip": None,
                        "ip_version": None,
                        "asn": None,
                        "asn_desc": None,
                        "org": None,
                        "country": None,
                        "registry": None,
                        "rdap_url": None,
                        "ok": "no",
                        "error": "no_ips_resolved",
                        "evidence_json": _safe_json(evidence),
                    }
                ],
            )

        # 2) ASN/Org/Country via RDAP (ipwhois)
        try:
            from ipwhois import IPWhois  # type: ignore
        except Exception as e:
            logger.warning("[ip_asn_geo] ipwhois missing -> skip enrichment domain=%s err=%s", domain, e)
            evidence = {
                "domain": domain,
                "checked_ts": checked_ts,
                "ips": all_ips,
                "derived": {"rotation": "unknown"},
                "errors": ["ipwhois_not_installed"],
            }
            # Без enrichment всё равно сохраним IP (это полезно) и отдадим warn/skip.
            payload = []
            for ip in all_ips:
                payload.append(
                    {
                        "checked_ts": checked_ts,
                        "ip": ip,
                        "ip_version": 6 if ":" in ip else 4,
                        "asn": None,
                        "asn_desc": None,
                        "org": None,
                        "country": None,
                        "registry": None,
                        "rdap_url": None,
                        "ok": "no",
                        "error": "ipwhois_not_installed",
                        "evidence_json": _safe_json(evidence),
                    }
                )

            return ModuleResult(
                check_updates=[
                    CheckUpdate(
                        key=self.key,
                        description="IP/ASN/география: собраны IP, но ASN/Geo пропущены (ipwhois не установлен)",
                        row=CheckRow(status="no", score=10, evidence_json=_safe_json(evidence)),
                    )
                ],
                module_payload=payload,
            )

        sem = asyncio.Semaphore(self.LOOKUP_CONCURRENCY)

        async def enrich_one(ip: str) -> IpEnrichment:
            # Ограничиваем конкурентность, чтобы не создать лавину RDAP запросов.
            async with sem:
                return await asyncio.to_thread(self._rdap_lookup, IPWhois, ip)

        tasks = [enrich_one(ip) for ip in all_ips]
        enriched = await asyncio.gather(*tasks)

        # 3) Производные выводы
        asns = sorted({e.asn for e in enriched if e.asn})
        countries = sorted({e.country for e in enriched if e.country})
        orgs = sorted({e.org for e in enriched if e.org})

        mass_infra = self._detect_mass_infra(enriched)

        evidence: dict[str, Any] = {
            "domain": domain,
            "checked_ts": checked_ts,
            "ips": all_ips,
            "enriched": [e.__dict__ for e in enriched],
            "derived": {
                "asns": asns,
                "countries": countries,
                "orgs": orgs,
                "mass_infrastructure_suspected": mass_infra["suspected"],
                "mass_infrastructure_signals": mass_infra["signals"],
                # rotation будет вычисляться на этапе build_report_block через сравнение с предыдущим запуском
                "rotation": "unknown",
            },
        }
        evidence_json = _safe_json(evidence)

        # 4) score/status
        # Базовая логика:
        # - OK если enrichment прошёл хотя бы для части IP
        # - warn если есть mass infra (это не плохо, но снижает определённость реального origin)
        # - warn если много стран/ASN (возможно балансировка/anycast — тоже не обязательно плохо)
        ok_count = sum(1 for e in enriched if e.error is None)
        status = "yes" if ok_count > 0 else "no"
        score = 60 if ok_count > 0 else 10
        if mass_infra["suspected"]:
            score = max(0, score - 10)
        if len(asns) >= 3:
            score = max(0, score - 10)
        if len(countries) >= 2:
            score = max(0, score - 5)
        score = min(100, score)

        logger.info(
            "[ip_asn_geo] done domain=%s status=%s score=%s ips=%s ok_enriched=%s asns=%s countries=%s mass=%s",
            domain,
            status,
            score,
            len(all_ips),
            ok_count,
            len(asns),
            len(countries),
            mass_infra["suspected"],
        )

        payload: list[dict] = []
        for e in enriched:
            payload.append(
                {
                    "checked_ts": checked_ts,
                    "ip": e.ip,
                    "ip_version": e.version,
                    "asn": e.asn,
                    "asn_desc": e.asn_description,
                    "org": e.org,
                    "country": e.country,
                    "registry": e.registry,
                    "rdap_url": e.rdap_url,
                    "ok": "yes" if e.error is None else "no",
                    "error": e.error,
                    "evidence_json": evidence_json,
                }
            )

        # Подложим производные данные в context — пригодится другим модулям (например, WAF/CDN детектору).
        context.data["ip_asn_geo"] = evidence["derived"]

        return ModuleResult(
            check_updates=[
                CheckUpdate(
                    key=self.key,
                    description="IP/ASN/география: IP, ASN, провайдер, страна и сигналы ротации/массовой инфраструктуры",
                    row=CheckRow(status=status, score=score, evidence_json=evidence_json),
                )
            ],
            module_payload=payload,
        )

    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        """Сохраняем факты в таблицу ip_asn_geo_checks (одна пачка = один checked_ts)."""
        if not payload:
            logger.debug("[ip_asn_geo] empty payload -> skip persist domain=%s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[ip_asn_geo] domain missing -> create domain=%s", domain)
            domain_record = create_domain(session, domain, source="audit")

        for item in payload:
            session.add(
                IpAsnGeoCheck(
                    domain_id=domain_record.id,
                    checked_ts=item.get("checked_ts", _now_ts()),
                    ip=item.get("ip"),
                    ip_version=item.get("ip_version"),
                    ok=item.get("ok", "no"),
                    asn=item.get("asn"),
                    asn_desc=item.get("asn_desc"),
                    org=item.get("org"),
                    country=item.get("country"),
                    registry=item.get("registry"),
                    rdap_url=item.get("rdap_url"),
                    error=item.get("error"),
                    evidence_json=item.get("evidence_json"),
                )
            )

        session.commit()
        logger.info("[ip_asn_geo] persisted domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        """
        Готовит Report v2 + legacy entries.
        Важно: здесь вычисляем ротацию IP, сравнивая последнюю пачку с предыдущей.
        """
        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            return self._empty_block("Данные о домене отсутствуют в базе.")

        last_ts = (
            session.query(IpAsnGeoCheck.checked_ts)
            .filter(IpAsnGeoCheck.domain_id == domain_record.id)
            .order_by(IpAsnGeoCheck.checked_ts.desc())
            .limit(1)
            .scalar()
        )
        if last_ts is None:
            return self._empty_block("Нет записей IP/ASN/география для домена.")

        rows = (
            session.query(IpAsnGeoCheck)
            .filter(IpAsnGeoCheck.domain_id == domain_record.id)
            .filter(IpAsnGeoCheck.checked_ts == last_ts)
            .order_by(IpAsnGeoCheck.ip.asc())
            .all()
        )

        # Предыдущая пачка для ротации
        prev_ts = (
            session.query(IpAsnGeoCheck.checked_ts)
            .filter(IpAsnGeoCheck.domain_id == domain_record.id)
            .filter(IpAsnGeoCheck.checked_ts < last_ts)
            .order_by(IpAsnGeoCheck.checked_ts.desc())
            .limit(1)
            .scalar()
        )
        prev_ips: set[str] = set()
        if prev_ts is not None:
            prev_rows = (
                session.query(IpAsnGeoCheck)
                .filter(IpAsnGeoCheck.domain_id == domain_record.id)
                .filter(IpAsnGeoCheck.checked_ts == prev_ts)
                .all()
            )
            prev_ips = {r.ip for r in prev_rows if r.ip}

        cur_ips = {r.ip for r in rows if r.ip}
        rotation = "unknown"
        rotation_details = None
        if prev_ts is not None:
            if cur_ips != prev_ips:
                rotation = "changed"
                rotation_details = {
                    "added": sorted(cur_ips - prev_ips),
                    "removed": sorted(prev_ips - cur_ips),
                }
            else:
                rotation = "stable"

        # evidence (единый) — возьмём из первой строки
        evidence = {}
        if rows and rows[0].evidence_json:
            try:
                evidence = json.loads(rows[0].evidence_json)
            except Exception:
                evidence = {}

        derived = (evidence.get("derived") or {}) if isinstance(evidence, dict) else {}
        derived["rotation"] = rotation
        if rotation_details:
            derived["rotation_details"] = rotation_details

        # KPI
        asns = sorted({r.asn for r in rows if r.asn})
        countries = sorted({r.country for r in rows if r.country})
        orgs = sorted({r.org for r in rows if r.org})

        mass = bool(derived.get("mass_infrastructure_suspected"))
        kpis = {
            "ip_count": len(cur_ips),
            "asn_count": len(asns),
            "country_count": len(countries),
            "rotation": rotation,
            "mass_infra": "yes" if mass else "no",
        }

        # Headline
        headline = "IP-профиль собран"
        if rotation == "changed":
            headline = "Обнаружена ротация IP"
        if mass:
            headline = "Обнаружены признаки массовой инфраструктуры"

        # Insights (короткие, практичные)
        insights: list[str] = []
        if asns:
            insights.append(f"ASN: {', '.join(asns[:3])}{'…' if len(asns) > 3 else ''}.")
        if orgs:
            insights.append(f"Провайдер/организация: {orgs[0]}{'' if len(orgs) == 1 else ' (и др.)'}.")
        if countries:
            insights.append(f"Страны по RDAP: {', '.join(countries)}.")
        if rotation == "changed" and rotation_details:
            insights.append(
                f"Ротация IP: добавлено {len(rotation_details['added'])}, удалено {len(rotation_details['removed'])}."
            )
        elif rotation == "stable":
            insights.append("Ротация IP не выявлена (по сравнению с предыдущим запуском).")
        else:
            insights.append("Ротация IP пока не определена (нет истории).")

        if mass:
            sig = derived.get("mass_infrastructure_signals") or []
            if sig:
                insights.append(f"Сигналы массовой инфраструктуры: {', '.join(sig)}.")
            else:
                insights.append("Сигналы массовой инфраструктуры обнаружены (эвристика).")
        else:
            insights.append("Явных признаков массовой инфраструктуры не обнаружено (эвристика).")

        # Timeline
        timeline = [
            {
                "timestamp": datetime.fromtimestamp(last_ts).strftime("%d.%m.%Y %H:%M:%S"),
                "status": "ok" if rows else "no_data",
                "title": "IP/ASN/география выполнен",
                "meta": {
                    "ip_count": len(cur_ips),
                    "rotation": rotation,
                },
            }
        ]
        if prev_ts is not None:
            timeline.append(
                {
                    "timestamp": datetime.fromtimestamp(prev_ts).strftime("%d.%m.%Y %H:%M:%S"),
                    "status": "info",
                    "title": "Предыдущий снимок (для сравнения ротации)",
                    "meta": {"ip_count": len(prev_ips)},
                }
            )

        # Табличная матрица для шаблона
        table_rows: list[dict] = []
        for r in rows:
            table_rows.append(
                {
                    "ip": r.ip,
                    "version": r.ip_version,
                    "asn": r.asn,
                    "org": r.org,
                    "country": r.country,
                    "registry": r.registry,
                    "asn_desc": r.asn_desc,
                    "rdap_url": r.rdap_url,
                    "ok": (r.ok == "yes"),
                    "error": r.error,
                }
            )

        # Legacy entries (последние 30 строк)
        last_rows = (
            session.query(IpAsnGeoCheck)
            .filter(IpAsnGeoCheck.domain_id == domain_record.id)
            .order_by(IpAsnGeoCheck.checked_ts.desc())
            .limit(30)
            .all()
        )
        entries = []
        for r in last_rows:
            ts_str = datetime.fromtimestamp(r.checked_ts).strftime("%d.%m.%Y %H:%M:%S")
            msg = "OK" if r.ok == "yes" else "FAIL"
            entries.append(
                {
                    "timestamp": ts_str,
                    "status": msg,
                    "message": f"{r.ip} (AS{r.asn})" if r.asn else f"{r.ip}",
                    "details": {
                        "org": r.org,
                        "country": r.country,
                        "error": r.error,
                    },
                }
            )

        summary = {
            "ip_count": len(cur_ips),
            "asn_count": len(asns),
            "country_count": len(countries),
            "rotation": rotation,
            "mass_infra": True if mass else False,
        }

        empty_message = ""
        if not rows:
            empty_message = "Нет данных IP/ASN/география для домена."

        return {
            "key": self.key,
            "template": "audit_modules/ip_asn_geo/ip_asn_geo.html",
            "name": self.name,
            "description": self.description,

            # старое — для текущего UI
            "summary": summary,
            "entries": entries,
            "empty_message": empty_message,

            # новое — для будущего UI
            "headline": headline,
            "kpis": {
                "ip_count": summary["ip_count"],
                "asn_count": summary["asn_count"],
                "country_count": summary["country_count"],
                "rotation": summary["rotation"],
                "mass_infra": "yes" if summary["mass_infra"] else "no",
            },
            "checks": {
                "sources": ["dns(A/AAAA)", "socket.getaddrinfo"],
                "asn_source": "rdap(ipwhois)",
                "rotation_based_on_history": True,
                "mass_infra_heuristics": list(MASS_INFRA_HINTS),
            },
            "insights": insights,
            "timeline": timeline,

            # данные для шаблона (таблица + детали ротации)
            "table": {
                "rows": table_rows,
                "rotation_details": rotation_details,
            },
        }

    # ----------------------- helpers -----------------------

    def _empty_block(self, message: str) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "entries": [],
            "empty_message": message,
            "headline": "Нет данных",
            "kpis": {},
            "insights": [],
            "timeline": [],
            "table": {"rows": [], "rotation_details": None},
        }

    def _collect_ips_from_context_or_dns(self, context: AuditContext) -> list[str]:
        """
        Пытаемся:
        1) взять IP из context.data (если предыдущие модули их сохранили),
        2) взять IP из DNS-аудита (если он хранит A/AAAA).
        """
        # 1) прямой кэш
        if "resolved_ips" in context.data and isinstance(context.data["resolved_ips"], list):
            return [str(x) for x in context.data["resolved_ips"]]

        # 2) использование данных dns-модуля (если вы туда позже добавите удобный список IP — модуль сразу начнёт им пользоваться)
        dns_derived = context.data.get("dns")
        if isinstance(dns_derived, dict):
            ips = dns_derived.get("ips")
            if isinstance(ips, list):
                return [str(x) for x in ips]

        # 3) ничего не нашли — вернём пусто
        return []

    def _collect_ips_socket(self, domain: str) -> list[str]:
        """
        Fallback на socket.getaddrinfo.
        Это не даёт TTL/NS, но даёт IP адреса достаточно надёжно.
        """
        ips: set[str] = set()
        try:
            infos = socket.getaddrinfo(domain, None)
            for family, _, _, _, sockaddr in infos:
                if family == socket.AF_INET:
                    ips.add(sockaddr[0])
                elif family == socket.AF_INET6:
                    ips.add(sockaddr[0])
        except Exception as e:
            logger.warning("[ip_asn_geo] socket.getaddrinfo failed domain=%s err=%s", domain, e)
        return sorted(ips)

    def _rdap_lookup(self, IPWhois, ip: str) -> IpEnrichment:
        """
        RDAP lookup через ipwhois (sync).
        Возвращаем нормализованную сущность.
        """
        version = 6 if ":" in ip else 4

        try:
            w = IPWhois(ip)
            # RDAP — предпочтительно. Иногда может фейлиться на сети/лимитах.
            res = w.lookup_rdap(depth=1)

            asn = res.get("asn")
            asn_desc = res.get("asn_description")
            registry = res.get("asn_registry")
            country = res.get("asn_country_code")
            rdap_url = None
            # ipwhois отдаёт ссылки не всегда одинаково; аккуратно.
            if isinstance(res.get("network"), dict):
                rdap_url = res["network"].get("rdap_url") or res["network"].get("remarks")

            # Организация: берём наиболее “человечное” поле.
            org = None
            if isinstance(res.get("network"), dict):
                org = res["network"].get("name") or res["network"].get("org")
            if not org:
                org = asn_desc

            logger.info(
                "[ip_asn_geo] rdap ok ip=%s asn=%s country=%s org=%s",
                ip,
                asn,
                country,
                org,
            )
            return IpEnrichment(
                ip=ip,
                version=version,
                asn=str(asn) if asn else None,
                asn_description=str(asn_desc) if asn_desc else None,
                org=str(org) if org else None,
                country=str(country) if country else None,
                registry=str(registry) if registry else None,
                rdap_url=str(rdap_url) if rdap_url else None,
                error=None,
            )
        except Exception as e:
            err = str(e)
            logger.warning("[ip_asn_geo] rdap fail ip=%s err=%s", ip, err)
            return IpEnrichment(
                ip=ip,
                version=version,
                asn=None,
                asn_description=None,
                org=None,
                country=None,
                registry=None,
                rdap_url=None,
                error=err,
            )

    def _detect_mass_infra(self, enriched: list[IpEnrichment]) -> dict[str, Any]:
        """
        Эвристика “массовой инфраструктуры”:
        - совпадение по org/asn_description с известными провайдерами CDN/крупных облаков
        - большое количество IP (anycast/balancing)
        """
        signals: list[str] = []
        joined = " ".join(
            [
                (e.org or "") + " " + (e.asn_description or "")
                for e in enriched
                if e.error is None
            ]
        ).lower()

        for hint in MASS_INFRA_HINTS:
            if hint in joined:
                signals.append(hint)

        ip_count = len({e.ip for e in enriched})
        if ip_count >= 6:
            signals.append(f"many_ips:{ip_count}")

        suspected = len(signals) > 0
        return {"suspected": suspected, "signals": sorted(set(signals))}


class IpAsnGeoCheck(Base):
    """
    Сырые факты IP/ASN/Geo.
    Один запуск = пачка строк с одинаковым checked_ts.
    """
    __tablename__ = "ip_asn_geo_checks"

    id = Column(Integer, primary_key=True, autoincrement=True)

    domain_id = Column(Integer, ForeignKey("domains.id"), index=True, nullable=False)
    checked_ts = Column(Integer, index=True, nullable=False)

    ip = Column(String(64), index=True, nullable=True)
    ip_version = Column(Integer, nullable=True)  # 4/6

    ok = Column(String(8), nullable=False)  # yes/no

    asn = Column(String(32), nullable=True)
    asn_desc = Column(Text, nullable=True)
    org = Column(Text, nullable=True)
    country = Column(String(8), nullable=True)
    registry = Column(String(32), nullable=True)
    rdap_url = Column(Text, nullable=True)

    error = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=True)
