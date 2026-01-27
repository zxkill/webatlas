## WebAtlas — аудит доменов, CMS и конфигурации
WebAtlas — масштабируемая платформа для инвентаризации доменов, определения CMS/фреймворков и безопасного технического аудита. Проект ориентирован на безопасность, автоматизацию и расширяемость: каждая проверка хранится отдельно, а база данных готова к росту количества CMS, админок и уязвимостей.

### Установка
pip install -r requirements.txt

### 1) Импорт доменов из 2ip API
python scripts/import_db.py

### 2) Импорт доменов из файла (по одному домену в строке)
Файл задаётся один раз в `config.yaml` в параметре `import.file_path`.
python scripts/import_from_file.py

### 3) Аудит доменов (базовая проверка Bitrix как одна из множества будущих проверок)
python scripts/audit_allowlist.py

### 4) Технический аудит доменов (неразрушающий pipeline)
Запуск сканирования доменов из БД с полным списком или лимитом:
python scripts/scan_domains.py
python scripts/scan_domains.py --limit 100

Получение отчёта и истории запусков:
python scripts/scan_report.py --domain example.com
python scripts/scan_report.py --scan-id 10
python scripts/scan_report.py --history --limit 20

### Возможности технического аудита
- Нормализация домена, проверка доступности, редиректы, тайминги.
- Сбор заголовков, проверка security headers и cookie-флагов.
- Быстрый TLS чек: issuer, SAN, срок действия.
- Пассивное определение технологий/стека.
- Безопасные проверки common paths (админки, публичные файлы).
- Ограниченный порт-чек популярных портов.
- Риск-скоринг и хранение результатов в БД.

### Структура БД и масштабирование
- `domains` — список доменов с дедупликацией и источником.
- `checks` / `domain_checks` — универсальные проверки (Bitrix — лишь одна из них).
- `cms` / `domain_cms` — результаты определения CMS.
- `admin_panels` — статусы доступности админок.
- `vulnerabilities` / `domain_vulnerabilities` — база для будущих уязвимостей.
- `scan_runs` / `scan_findings` — история запусков технического аудита и findings.

### Ключевые особенности
- Поддержка массового импорта доменов и проверка на дубли.
- Готовая база для масштабного аудитора CMS/фреймворков и уязвимостей.
- Подробное логирование для мониторинга и отладки.
- Безопасный технический аудит с risk-скором и отчётами.

### SEO ключевые слова
Domain audit, CMS detection, security scanning, vulnerability management, configuration exposure, TLS checks, Web security automation, WebAtlas.
