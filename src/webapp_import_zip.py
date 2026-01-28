from __future__ import annotations

import logging
import tempfile
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

def download_zip(url: str, timeout: int = 120) -> Path:
    req = Request(url, headers={"User-Agent": "webatlas/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    tmp = Path(tempfile.mkstemp(suffix=".zip")[1])
    tmp.write_bytes(data)
    logger.info("ZIP скачан: %s (%s bytes)", tmp, tmp.stat().st_size)
    return tmp

def extract_txt_from_zip(zip_path: Path, preferred_name: str | None = None) -> Path:
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()

        candidate = None
        if preferred_name:
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
            raise FileNotFoundError("В ZIP не найден TXT файл")

        out_dir = Path(tempfile.mkdtemp(prefix="webatlas_import_"))
        out_path = out_dir / Path(candidate).name
        with zf.open(candidate) as src, open(out_path, "wb") as dst:
            dst.write(src.read())

        logger.info("TXT извлечён: %s", out_path)
        return out_path
