from __future__ import annotations

import logging

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from src.webapp_config import load_webapp_config
from src.webapp_db import create_db_state, init_db, list_domains
from src.webapp_logging import configure_logging
from src.webapp_tasks import add_domain_task

configure_logging()
logger = logging.getLogger(__name__)

config = load_webapp_config()
state = create_db_state(config.database_url)
init_db(state)

app = FastAPI(title="WebAtlas UI", version="1.0.0")


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    """
    Простая веб-страница со списком доменов и формой добавления.

    Мы генерируем HTML вручную, чтобы не тянуть дополнительные зависимости.
    """

    logger.info("Запрос главной страницы")
    with state.session_factory() as session:
        domains = list_domains(session)

    rows = "".join(
        f"<tr><td>{item.id}</td><td>{item.domain}</td><td>{item.source}</td></tr>" for item in domains
    )
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
        </style>
      </head>
      <body>
        <h1>WebAtlas: быстрый аудит доменов</h1>
        <p>Добавьте домен для фоновой обработки (Celery + Redis).</p>
        <form method=\"post\" action=\"/enqueue\">
          <div class=\"form-row\">
            <label>Домен:</label>
            <input type=\"text\" name=\"domain\" placeholder=\"example.com\" required />
          </div>
          <button type=\"submit\">Поставить в очередь</button>
        </form>
        <h2>Последние домены</h2>
        <table>
          <thead>
            <tr><th>ID</th><th>Домен</th><th>Источник</th></tr>
          </thead>
          <tbody>
            {rows if rows else '<tr><td colspan="3">Данных пока нет</td></tr>'}
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
