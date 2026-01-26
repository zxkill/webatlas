from src.config import load_config
from src.importer_2ip import TwoIpImporter

def main() -> None:
    cfg = load_config()
    TwoIpImporter(cfg).run()

if __name__ == "__main__":
    main()
