import logging
import sys

from src.config import load_config
from src.importer_file import DomainFileImporter


def main() -> None:
    # Базовая настройка логирования для CLI-скрипта.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config()

    if len(sys.argv) < 2:
        raise SystemExit("Укажите путь к файлу со списком доменов: python scripts/import_from_file.py domains.txt")

    file_path = sys.argv[1]
    DomainFileImporter(cfg.db.path).run(file_path, source="file")


if __name__ == "__main__":
    main()
