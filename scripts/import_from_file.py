import logging

from src.config import load_config
from src.importer_file import DomainFileImporter


def main() -> None:
    # Базовая настройка логирования для CLI-скрипта.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config()

    # Файл со списком доменов задаётся в конфигурации, чтобы путь был единым.
    file_path = cfg.import_cfg.file_path
    logging.getLogger(__name__).info("Используем файл доменов из конфига: %s", file_path)
    DomainFileImporter(cfg.db.url).run(file_path, source="file")


if __name__ == "__main__":
    main()
