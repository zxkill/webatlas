from __future__ import annotations

from collections.abc import Generator

from src.settings.loader import load_settings
from src.webapp_db import create_db_state, init_db

settings = load_settings()

state = create_db_state(settings.runtime.database_url)
init_db(state)


def get_session() -> Generator:
    with state.session_factory() as session:
        yield session
