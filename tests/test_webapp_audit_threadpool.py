import asyncio

from src.webapp_audit import _configure_threadpool


class _FakeLoop:
    def __init__(self) -> None:
        self.executor = None

    def set_default_executor(self, executor) -> None:
        self.executor = executor


def test_configure_threadpool_sets_executor(monkeypatch) -> None:
    """
    Проверяем, что threadpool выставляется как default executor event loop.
    """
    fake_loop = _FakeLoop()
    monkeypatch.setattr("src.webapp_audit.asyncio.get_running_loop", lambda: fake_loop)

    executor = _configure_threadpool(4)

    assert fake_loop.executor is executor
    executor.shutdown(wait=True)
