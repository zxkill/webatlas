import argparse
import logging

from src.config import load_config
from src.scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Запуск безопасного технического сканирования доменов из БД."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Ограничить количество доменов из БД (по умолчанию — все).",
    )
    return parser


def main() -> None:
    # Детальное логирование для мониторинга прогресса.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args()
    cfg = load_config()
    Scanner(cfg).run(limit=args.limit)


if __name__ == "__main__":
    main()
