from __future__ import annotations

from urllib.parse import urlparse
import logging
import tldextract

logger = logging.getLogger(__name__)


def normalize_domain(raw: str) -> str | None:
    """
    Нормализует домен:
    - обрезает пробелы и приводит к lower-case,
    - удаляет логин/пароль и порт,
    - выделяет домен+зону+поддомен,
    - игнорирует комментарии и некорректные строки.
    """
    # Защита от пустых строк и комментариев.
    raw = (raw or "").strip().lower()
    if not raw or raw.startswith("#"):
        logger.debug("Строка пропущена: пустая или комментарий.")
        return None

    # Поддержка форматов: domain.tld, http(s)://domain.tld/path, user:pass@domain.tld:port
    if "://" in raw:
        parsed = urlparse(raw)
        candidate = parsed.netloc or parsed.path
    else:
        candidate = raw

    # Удаляем возможный логин и порт.
    candidate = candidate.split("@")[-1].split(":")[0].strip()
    logger.debug("Кандидат домена после очистки: %s", candidate)
    ext = tldextract.extract(candidate)
    if not ext.domain or not ext.suffix:
        logger.debug("Строка не похожа на домен: %s", raw)
        return None

    normalized = ".".join(part for part in [ext.subdomain, ext.domain, ext.suffix] if part)
    logger.debug("Нормализованный домен: %s", normalized)
    return normalized or None

