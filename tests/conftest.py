import sys
from pathlib import Path

# Добавляем корень репозитория в sys.path, чтобы тесты находили пакет src.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
