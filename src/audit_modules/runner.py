from __future__ import annotations

import logging
from collections import deque
from collections.abc import Iterable

from src.audit_modules.registry import get_registry, resolve_module_plan
from src.audit_modules.types import AuditContext, ModuleResult, ModuleRunSummary

logger = logging.getLogger(__name__)


async def run_modules_for_domain(
    context: AuditContext,
    selected_modules: Iterable[str] | None = None,
) -> ModuleRunSummary:
    """
    Запускает модули аудита для одного домена с учётом зависимостей.

    Возвращает агрегированный результат для последующей записи в БД.
    """

    registry = get_registry()
    module_queue = deque(resolve_module_plan(selected_modules))
    summary = ModuleRunSummary()
    executed: set[str] = set()

    while module_queue:
        module_key = module_queue.popleft()
        if module_key in executed:
            continue

        module = registry.get(module_key)
        if module is None:
            logger.warning("Модуль %s отсутствует в реестре", module_key)
            continue

        unmet_deps = [dep for dep in module.depends_on if dep not in executed]
        if unmet_deps:
            # Добавляем в очередь после зависимостей, чтобы соблюсти порядок выполнения.
            logger.debug("Модуль %s ждёт зависимости: %s", module_key, unmet_deps)
            module_queue.append(module_key)
            for dep in unmet_deps:
                if dep not in executed:
                    module_queue.appendleft(dep)
            continue

        logger.info("Запуск модуля %s для домена %s", module_key, context.domain)
        result = await module.run(context)
        summary.merge(result, module_key)
        executed.add(module_key)

        # Если модуль доступности показал недоступность, прекращаем дальнейший аудит домена.
        if module_key == "availability":
            availability = context.data.get("availability", {})
            if not availability.get("reachable", False):
                logger.info(
                    "Останавливаем аудит домена %s: сайт недоступен, остальные модули пропущены",
                    context.domain,
                )
                break

        # Динамически подключаем дополнительные модули (например, для CMS).
        for extra_key in result.additional_modules:
            if extra_key not in executed:
                logger.info("Добавляем модуль %s по результатам аудита", extra_key)
                module_queue.append(extra_key)

    return summary
