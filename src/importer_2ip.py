from __future__ import annotations

import asyncio
import logging
import aiohttp

from .config import AppConfig
from .db import Database
from .http import HttpClient
from .domain_utils import normalize_domain

logger = logging.getLogger(__name__)


class TwoIpImporter:
    """Импорт доменов из 2ip API в PostgreSQL."""

    def __init__(self, cfg: AppConfig) -> None:
        self._cfg = cfg

    def run(self) -> None:
        asyncio.run(self._run_async())

    async def _run_async(self) -> None:
        db = Database(self._cfg.db.url)
        http = HttpClient(rps=self._cfg.rate_limit.rps, total_timeout_s=self._cfg.audit.timeouts.total)

        token = self._cfg.import_cfg.token
        tpl = self._cfg.import_cfg.api_url_template
        max_domains = self._cfg.import_cfg.max_domains

        imported = 0

        async with aiohttp.ClientSession() as session:
            # первая страница — чтобы узнать total_pages
            first_url = tpl.format(page=1, token=token)
            data = await http.get_json(session, first_url)
            total_pages = int(data.get("pagination", {}).get("total_pages", 1))

            def ingest(domains: list[str]) -> int:
                # Импортируем домены по одной странице.
                # Здесь важно отсекать дубли и невалидные строки.
                nonlocal imported
                added = 0
                for d in domains or []:
                    if imported >= max_domains:
                        break
                    nd = normalize_domain(d)
                    if not nd:
                        continue
                    db.upsert_domain(nd, source="2ip")
                    imported += 1
                    added += 1
                return added

            added = ingest(data.get("domains", []))
            db.commit()
            logger.info("[import] page 1/%s: +%s, total=%s", total_pages, added, imported)

            page = 2
            while page <= total_pages and imported < max_domains:
                url = tpl.format(page=page, token=token)
                data = await http.get_json(session, url)
                added = ingest(data.get("domains", []))
                db.commit()
                logger.info("[import] page %s/%s: +%s, total=%s", page, total_pages, added, imported)
                page += 1

        db.close()
        logger.info("[import] completed. Imported=%s", imported)
