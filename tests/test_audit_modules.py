import pytest

# Пропускаем тесты модулей, если SQLAlchemy недоступен.
pytest.importorskip("sqlalchemy")

from src.audit_modules.registry import resolve_module_plan


def test_resolve_module_plan_defaults_to_all() -> None:
    # По умолчанию все модули должны быть включены.
    plan = resolve_module_plan(None)
    assert "availability" in plan
    assert "bitrix_detect" in plan
    assert "tls_certificate" in plan


def test_resolve_module_plan_adds_dependencies() -> None:
    # При выборе admin-модуля должны подтянуться зависимости.
    plan = resolve_module_plan(["bitrix_admin"])
    assert plan.index("availability") < plan.index("bitrix_detect")
    assert plan.index("bitrix_detect") < plan.index("bitrix_admin")
