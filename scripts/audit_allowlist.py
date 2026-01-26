from src.config import load_config
from src.auditor import Auditor

def main() -> None:
    cfg = load_config()
    Auditor(cfg).run()

if __name__ == "__main__":
    main()
