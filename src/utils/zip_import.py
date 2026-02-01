from __future__ import annotations

import logging
import tempfile
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "WebAtlas/1.0"


def download_zip(
    url: str,
    *,
    timeout: int = 120,
    user_agent: str = DEFAULT_USER_AGENT,
    chunk_size: int = 1024 * 256,
) -> Path:
    """
    Скачивает ZIP-файл по URL во временный файл (стриминг, без загрузки всего в память).

    :param url: URL архива
    :param timeout: таймаут запроса (сек)
    :param user_agent: User-Agent для HTTP-запроса
    :param chunk_size: размер чанка при чтении (байт)
    :return: путь к временному ZIP-файлу
    """
    logger.info("Скачивание ZIP: %s", url)

    req = Request(url, headers={"User-Agent": user_agent})
    tmp_path = Path(tempfile.mkstemp(suffix=".zip")[1])

    total = 0
    with urlopen(req, timeout=timeout) as resp, tmp_path.open("wb") as out:
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            out.write(chunk)
            total += len(chunk)

    logger.info("ZIP скачан: %s (%s bytes)", tmp_path, total)
    return tmp_path


def extract_txt_from_zip(
    zip_path: Path,
    *,
    preferred_name: str | None = None,
) -> Path:
    """
    Извлекает TXT-файл из ZIP-архива.

    Логика выбора файла:
    1) если указан preferred_name — ищем по имени
    2) иначе берём первый *.txt
    3) если TXT не найден — ошибка

    :param zip_path: путь к ZIP
    :param preferred_name: ожидаемое имя файла (опционально)
    :return: путь к извлечённому TXT
    """
    logger.info("Извлечение TXT из ZIP: %s", zip_path)

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        candidate: str | None = None

        if preferred_name:
            preferred_basename = Path(preferred_name).name
            for name in names:
                if Path(name).name == preferred_basename:
                    candidate = name
                    break

        if not candidate:
            for name in names:
                if name.lower().endswith(".txt"):
                    candidate = name
                    break

        if not candidate:
            logger.error("В ZIP не найден TXT файл: %s", zip_path)
            raise FileNotFoundError("В ZIP не найден TXT файл")

        out_dir = Path(tempfile.mkdtemp(prefix="webatlas_import_"))
        out_path = out_dir / Path(candidate).name

        with zf.open(candidate) as src, out_path.open("wb") as dst:
            # Читаем блоками — полезно на крупных txt
            while True:
                chunk = src.read(1024 * 256)
                if not chunk:
                    break
                dst.write(chunk)

        logger.info("TXT извлечён: %s", out_path)
        return out_path
