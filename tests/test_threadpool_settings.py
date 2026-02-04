from src.settings import loader


def test_resolve_threadpool_workers_uses_explicit_value() -> None:
    """
    Проверяем, что явное значение threadpool_workers берётся без изменений.
    """
    audit = {"threadpool_workers": 123}
    assert loader._resolve_threadpool_workers(audit) == 123


def test_resolve_threadpool_workers_uses_cpu_heuristic(monkeypatch) -> None:
    """
    Проверяем, что при отсутствии явной настройки используется эвристика по CPU.
    """
    monkeypatch.setattr(loader.os, "cpu_count", lambda: 4)
    audit = {}
    # 4 * 8 = 32, но минимум 64, поэтому ожидаем 64.
    assert loader._resolve_threadpool_workers(audit) == 64
