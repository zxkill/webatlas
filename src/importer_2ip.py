from __future__ import annotations

import asyncio
from urllib.parse import urlparse
import aiohttp
import tldextract

from .config import AppConfig
from .db import Database
from .http import HttpClient


def normalize_domain(raw: str) -> str | None:
    raw = (raw or "").strip().lower()
    if not raw or raw.startswith("#"):
        return None

    if "://" in raw:
        p = urlparse(raw)
        candidate = p.netloc or p.path
    else:
        candidate = raw

    candidate = candidate.split("@")[-1].split(":")[0].strip()
    ext = tldextract.extract(candidate)
    if not ext.domain or not ext.suffix:
        return None

    return ".".join(part for part in [ext.subdomain, ext.domain, ext.suffix] if part)


class TwoIpImporter:
    """Импорт доменов из 2ip API в локальную SQLite-базу."""

    def __init__(self, cfg: AppConfig) -> None:
        self._cfg = cfg

    def run(self) -> None:
        asyncio.run(self._run_async())

    async def _run_async(self) -> None:
        db = Database(self._cfg.db.path)
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
            print(f"[import] page 1/{total_pages}: +{added}, total={imported}")

            page = 2
            while page <= total_pages and imported < max_domains:
                url = tpl.format(page=page, token=token)
                data = await http.get_json(session, url)
                added = ingest(data.get("domains", []))
                db.commit()
                print(f"[import] page {page}/{total_pages}: +{added}, total={imported}")
                page += 1

        db.close()
        print(f"[import] completed. Imported={imported}")
