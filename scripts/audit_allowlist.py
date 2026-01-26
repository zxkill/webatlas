import logging

from src.config import load_config
from src.auditor import Auditor

def main() -> None:
    # Базовая настройка логирования для CLI-скрипта.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    Auditor(cfg).run()

if __name__ == "__main__":
    main()
