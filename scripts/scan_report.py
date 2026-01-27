import argparse
import json
import logging

from src.config import load_config
from src.db import Database


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Просмотр отчётов сканирования WebAtlas.")
    parser.add_argument("--domain", help="Домен для получения последнего отчёта.")
    parser.add_argument("--scan-id", type=int, help="Конкретный ScanRun ID.")
    parser.add_argument("--history", action="store_true", help="Показать историю запусков.")
    parser.add_argument("--limit", type=int, default=20, help="Лимит записей истории.")
    return parser


def main() -> None:
    # Базовое логирование для CLI.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args()
    cfg = load_config()
    db = Database(cfg.db.path)

    try:
        if args.history:
            runs = db.list_scan_runs(domain=args.domain, limit=args.limit)
            print(json.dumps(runs, ensure_ascii=False, indent=2))
            return

        if args.scan_id:
            report = db.get_scan_report(args.scan_id)
            if report is None:
                raise SystemExit("ScanRun не найден.")
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return

        if args.domain:
            report = db.get_latest_scan_report(args.domain)
            if report is None:
                raise SystemExit("Отчёт не найден для указанного домена.")
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return

        raise SystemExit("Укажите --domain, --scan-id или --history.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
