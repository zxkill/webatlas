import logging

from src.config import load_config
from src.importer_2ip import TwoIpImporter

def main() -> None:
    # Базовая настройка логирования для CLI-скрипта.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    TwoIpImporter(cfg).run()

if __name__ == "__main__":
    main()
