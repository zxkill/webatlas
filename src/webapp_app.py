from __future__ import annotations

import logging

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from src.audit_modules.registry import list_modules
from src.config import load_config
from src.webapp_config import load_webapp_config
from src.webapp_db import create_db_state, get_domain_report, init_db, list_domains
from src.webapp_logging import configure_logging
from src.webapp_tasks import (
    add_domain_task,
    audit_all_task,
    audit_domain_task,
    audit_limit_task,
    import_domains_from_file_task,
)

configure_logging()
logger = logging.getLogger(__name__)

config = load_webapp_config()
app_cfg = load_config()
state = create_db_state(config.database_url)
init_db(state)

app = FastAPI(title="WebAtlas UI", version="1.2.0")


def _render_module_checkboxes() -> str:
    """
    Формирует HTML с чекбоксами модулей аудита.

    По умолчанию все модули отмечены, чтобы аудит запускался полноценно.
    """

    items = []
    for module in list_modules():
        items.append(
            "<label>"
            f"<input type='checkbox' name='modules' value='{module.key}' checked />"
            f"{module.name}"
            f"<span class='module-desc'>{module.description}</span>"
            "</label>"
        )
    return "\n".join(items)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    """
    Простая веб-страница со списком доменов и админскими действиями.

    Мы генерируем HTML вручную, чтобы не тянуть дополнительные зависимости.
    """

    logger.info("Запрос главной страницы")
    with state.session_factory() as session:
        domains = list_domains(session)

    rows = "".join(
        "<tr>"
        f"<td>{item.id}</td>"
        f"<td>{item.domain}</td>"
        f"<td>{item.source}</td>"
        f"<td><a href='/report/{item.domain}'>Отчёт</a></td>"
        "</tr>"
        for item in domains
    )

    modules_html = _render_module_checkboxes()

    return f"""
    <html lang=\"ru\">
      <head>
        <meta charset=\"utf-8\" />
        <title>WebAtlas — домены</title>
        <style>
          body {{ font-family: Arial, sans-serif; margin: 40px; }}
          table {{ border-collapse: collapse; width: 100%; }}
          th, td {{ border: 1px solid #ddd; padding: 8px; }}
          th {{ background: #f3f3f3; text-align: left; }}
          .form-row {{ margin-bottom: 16px; }}
          .card {{ border: 1px solid #eee; padding: 16px; margin-bottom: 24px; }}
          .actions {{ display: flex; gap: 16px; flex-wrap: wrap; }}
          .module-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 8px; }}
          .module-desc {{ display: block; font-size: 12px; color: #666; }}
        </style>
      </head>
      <body>
        <h1>WebAtlas: быстрый аудит доменов</h1>
        <p>Админка позволяет импортировать домены, запускать аудит и смотреть отчёты.</p>

        <div class=\"card\">
          <h2>Добавление домена вручную</h2>
          <form method=\"post\" action=\"/enqueue\">
            <div class=\"form-row\">
              <label>Домен:</label>
              <input type=\"text\" name=\"domain\" placeholder=\"example.com\" required />
            </div>
            <button type=\"submit\">Поставить в очередь</button>
          </form>
        </div>

        <div class=\"card\">
          <h2>Админские действия</h2>
          <div class=\"actions\">
            <form method=\"post\" action=\"/admin/import-file\">
              <input type=\"hidden\" name=\"file_path\" value=\"{app_cfg.import_cfg.file_path}\" />
              <button type=\"submit\">Импортировать домены из файла</button>
            </form>
            <form method=\"post\" action=\"/admin/audit-all\">
              <p>Модули аудита (по умолчанию включены все):</p>
              <div class=\"module-grid\">
                {modules_html}
              </div>
              <button type=\"submit\">Аудит всех доменов</button>
            </form>
            <form method=\"post\" action=\"/admin/audit-limit\">
              <input type=\"number\" name=\"limit\" min=\"1\" value=\"50\" required />
              <p>Модули аудита (по умолчанию включены все):</p>
              <div class=\"module-grid\">
                {modules_html}
              </div>
              <button type=\"submit\">Аудит с лимитом</button>
            </form>
            <form method=\"post\" action=\"/admin/audit-domain\">
              <input type=\"text\" name=\"domain\" placeholder=\"example.com\" required />
              <p>Модули аудита (по умолчанию включены все):</p>
              <div class=\"module-grid\">
                {modules_html}
              </div>
              <button type=\"submit\">Аудит домена</button>
            </form>
            <form method=\"get\" action=\"/report\">
              <input type=\"text\" name=\"domain\" placeholder=\"example.com\" required />
              <button type=\"submit\">Отчёт по домену</button>
            </form>
          </div>
          <p>Файл импорта: <strong>{app_cfg.import_cfg.file_path}</strong></p>
        </div>

        <h2>Последние домены</h2>
        <table>
          <thead>
            <tr><th>ID</th><th>Домен</th><th>Источник</th><th>Отчёт</th></tr>
          </thead>
          <tbody>
            {rows if rows else '<tr><td colspan="4">Данных пока нет</td></tr>'}
          </tbody>
        </table>
      </body>
    </html>
    """


@app.post("/enqueue")
def enqueue_domain(domain: str = Form(...)) -> RedirectResponse:
    """
    Принимает домен от пользователя и отправляет задачу в Celery.

    Возвращаем редирект, чтобы пользователь сразу видел обновлённый список.
    """

    logger.info("Постановка домена в очередь: %s", domain)
    add_domain_task.delay(domain.strip(), source="ui")
    return RedirectResponse(url="/", status_code=303)


@app.post("/admin/import-file")
def import_file(file_path: str = Form(...)) -> RedirectResponse:
    """Запускает импорт доменов из файла через Celery."""

    logger.info("Запуск импорта доменов из файла через админку: %s", file_path)
    import_domains_from_file_task.delay(file_path)
    return RedirectResponse(url="/", status_code=303)


@app.post("/admin/audit-all")
def audit_all(modules: list[str] | None = Form(None)) -> RedirectResponse:
    """Запускает аудит всех доменов через Celery."""

    logger.info("Запуск аудита всех доменов через админку: modules=%s", modules)
    audit_all_task.delay(modules)
    return RedirectResponse(url="/", status_code=303)


@app.post("/admin/audit-limit")
def audit_limit(limit: int = Form(...), modules: list[str] | None = Form(None)) -> RedirectResponse:
    """Запускает аудит ограниченного списка доменов."""

    logger.info("Запуск аудита доменов через админку с лимитом: %s, modules=%s", limit, modules)
    audit_limit_task.delay(limit, modules)
    return RedirectResponse(url="/", status_code=303)


@app.post("/admin/audit-domain")
def audit_domain(domain: str = Form(...), modules: list[str] | None = Form(None)) -> RedirectResponse:
    """Запускает аудит конкретного домена."""

    logger.info("Запуск аудита домена через админку: %s, modules=%s", domain, modules)
    # Передаём домен позиционно, а модули — через заголовки:
    # 1) Это устраняет ошибки, когда воркер ожидает только positional args.
    # 2) Заголовки доступны внутри задачи и не конфликтуют с сигнатурой.
    task_headers = {"modules": modules} if modules else None
    audit_domain_task.apply_async(args=[domain], headers=task_headers)
    return RedirectResponse(url="/", status_code=303)


@app.get("/report", response_class=HTMLResponse)
def report_query(domain: str) -> HTMLResponse:
    """Промежуточный эндпоинт для отчёта по домену из формы."""

    return report_domain(domain)


@app.get("/report/{domain}", response_class=HTMLResponse)
def report_domain(domain: str) -> HTMLResponse:
    """Отображает отчёт по домену."""

    logger.info("Запрос отчёта по домену: %s", domain)
    with state.session_factory() as session:
        report = get_domain_report(session, domain)

    if report is None:
        return HTMLResponse(
            content=f"<h1>Отчёт не найден</h1><p>Домен {domain} отсутствует в базе.</p>",
            status_code=404,
        )

    checks_html = "".join(
        "<li>"
        f"{item['key']}: статус={item['status']}, score={item['score']}"
        "</li>"
        for item in report["checks"]
    ) or "<li>Проверок пока нет</li>"
    cms_html = "".join(
        "<li>"
        f"{item['name']} ({item['key']}): статус={item['status']}, confidence={item['confidence']}"
        "</li>"
        for item in report["cms"]
    ) or "<li>CMS пока нет</li>"
    admin_html = "".join(
        "<li>"
        f"{item['panel_key']}: статус={item['status']}, http={item['http_status']}"
        "</li>"
        for item in report["admin_panels"]
    ) or "<li>Админки пока нет</li>"

    return HTMLResponse(
        content=f"""
        <html lang=\"ru\">
          <head>
            <meta charset=\"utf-8\" />
            <title>Отчёт по домену {report['domain']}</title>
            <style>
              body {{ font-family: Arial, sans-serif; margin: 40px; }}
              .section {{ margin-bottom: 24px; }}
            </style>
          </head>
          <body>
            <a href=\"/\">← Назад</a>
            <h1>Отчёт по домену: {report['domain']}</h1>
            <p>Источник: {report['source']}</p>
            <p>Создан: {report['created_at']} | Обновлён: {report['updated_at']}</p>

            <div class=\"section\">
              <h2>Проверки</h2>
              <ul>{checks_html}</ul>
            </div>
            <div class=\"section\">
              <h2>CMS</h2>
              <ul>{cms_html}</ul>
            </div>
            <div class=\"section\">
              <h2>Админки</h2>
              <ul>{admin_html}</ul>
            </div>
          </body>
        </html>
        """,
    )
