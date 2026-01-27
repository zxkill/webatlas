## WebAtlas — аудит доменов, CMS и уязвимостей с веб-интерфейсом
WebAtlas — масштабируемая платформа для инвентаризации доменов, определения CMS/фреймворков и будущего поиска уязвимостей. Проект теперь включает веб-интерфейс, фоновые задачи Celery и инфраструктуру Docker Compose с PostgreSQL и Redis.

### Возможности
- Импорт и аудит доменов через скрипты.
- Веб-интерфейс для постановки доменов в очередь обработки.
- Фоновая обработка через Celery и Redis.
- База данных PostgreSQL для устойчивого хранения.
- Подробное логирование для мониторинга и отладки.

### Быстрый старт через Docker Compose
1) Соберите и запустите сервисы:
```
docker compose up --build
```
2) Откройте веб-интерфейс на нестандартном порту:
```
http://localhost:8088
```

### Работа со скриптами (локальный запуск)
1) Установка зависимостей:
```
pip install -r requirements.txt
```
2) Импорт доменов из 2ip API:
```
python scripts/import_db.py
```
3) Импорт доменов из файла (по одному домену в строке):
```
python scripts/import_from_file.py
```
4) Аудит доменов (базовая проверка Bitrix):
```
python scripts/audit_allowlist.py
```

### Переменные окружения для веб-интерфейса
- `DATABASE_URL` — строка подключения к PostgreSQL.
- `REDIS_URL` — базовый адрес Redis.
- `CELERY_BROKER_URL` — брокер Celery (обычно Redis).
- `CELERY_BACKEND_URL` — backend Celery для результатов.
- `APP_HOST` и `APP_PORT` — параметры запуска веб-сервера.

### SEO ключевые слова
Domain audit, CMS detection, vulnerability scanning, web security automation, PostgreSQL, Redis, Celery, Docker Compose, WebAtlas.
