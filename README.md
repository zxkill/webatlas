### Установка
pip install -r requirements.txt

### 1) Импорт доменов из 2ip API
python scripts/import_db.py

### 2) Аудит доменов (только allowlist)
python scripts/audit_allowlist.py
