from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import urlparse

import tldextract

logger = logging.getLogger(__name__)


def normalize_domain(raw: str) -> str | None:
    """
    Нормализует домен:
    - обрезает пробелы, приводит к lower-case,
    - игнорирует комментарии/пустые строки,
    - поддерживает domain.tld, http(s)://domain.tld/path, user:pass@domain.tld:port,
    - выделяет subdomain + domain + suffix через tldextract,
    - возвращает None, если строка не похожа на домен.
    """
    raw = (raw or "").strip().lower()
    if not raw or raw.startswith("#"):
        logger.debug("Строка пропущена: пустая или комментарий.")
        return None

    # Поддержка URL-форматов
    if "://" in raw:
        parsed = urlparse(raw)
        candidate = parsed.netloc or parsed.path
    else:
        candidate = raw

    # Удаляем userinfo и порт
    candidate = candidate.split("@")[-1].split(":")[0].strip()
    if not candidate:
        logger.debug("Строка не похожа на домен (пустой кандидат): %s", raw)
        return None

    ext = tldextract.extract(candidate)
    if not ext.domain or not ext.suffix:
        logger.debug("Строка не похожа на домен: %s", raw)
        return None

    normalized = ".".join(part for part in (ext.subdomain, ext.domain, ext.suffix) if part)
    logger.debug("Нормализованный домен: %s -> %s", raw, normalized)
    return normalized or None


def iter_normalized_domains(lines: Iterable[str]) -> Iterator[str]:
    """
    Потоково нормализует домены из набора строк.

    Важно: возвращает только валидные домены (None отбрасывается).
    """
    for line in lines:
        normalized = normalize_domain(line)
        if normalized is not None:
            yield normalized


def iter_normalized_domains_from_file(path: str | Path, *, encoding: str = "utf-8") -> Iterator[str]:
    """
    Потоково читает файл и возвращает нормализованные домены.

    Память:
      - O(1) по входу (чтение построчно)
    """
    p = Path(path)
    if not p.exists():
        logger.error("Файл со списком доменов не найден: %s", p)
        raise FileNotFoundError(str(p))

    with p.open("r", encoding=encoding) as f:
        yield from iter_normalized_domains(f)
