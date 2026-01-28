from __future__ import annotations

import logging
import os
import tempfile
import zipfile
from pathlib import Path
from urllib.request import urlopen, Request

logger = logging.getLogger(__name__)

def download_zip(url: str, timeout: int = 60) -> Path:
    logger.info("Скачивание ZIP: %s", url)
    req = Request(url, headers={"User-Agent": "WebAtlas/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        data = resp.read()

    tmp = Path(tempfile.mkstemp(suffix=".zip")[1])
    tmp.write_bytes(data)
    logger.info("ZIP скачан: %s (%s bytes)", tmp, tmp.stat().st_size)
    return tmp

def extract_txt_from_zip(zip_path: Path, preferred_name: str | None = None) -> Path:
    """
    Возвращает путь к извлечённому TXT.
    Если preferred_name задан — пытается найти файл по имени в архиве.
    Иначе берёт первый *.txt.
    """
    logger.info("Извлечение TXT из ZIP: %s", zip_path)
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()

        candidate = None
        if preferred_name:
            # допускаем, что в архиве может быть путь вроде "ru.txt"
            for n in names:
                if Path(n).name == Path(preferred_name).name:
                    candidate = n
                    break

        if not candidate:
            for n in names:
                if n.lower().endswith(".txt"):
                    candidate = n
                    break

        if not candidate:
            raise FileNotFoundError("В ZIP не найден txt файл")

        out_dir = Path(tempfile.mkdtemp(prefix="webatlas_import_"))
        out_path = out_dir / Path(candidate).name
        with zf.open(candidate) as src, open(out_path, "wb") as dst:
            dst.write(src.read())

        logger.info("TXT извлечён: %s", out_path)
        return out_path
