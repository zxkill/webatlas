from __future__ import annotations

from collections.abc import Generator

from src.webapp_config import load_webapp_config
from src.webapp_db import create_db_state, init_db

config = load_webapp_config()
state = create_db_state(config.database_url)
init_db(state)


def get_session() -> Generator:
    with state.session_factory() as session:
        yield session
