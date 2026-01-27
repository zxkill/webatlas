# Базовый образ с Python, чтобы сборка была компактной и предсказуемой.
FROM python:3.11-slim

# Рабочая директория приложения внутри контейнера.
WORKDIR /app

# Сначала копируем зависимости, чтобы использовать Docker cache.
COPY requirements.txt ./
# Устанавливаем зависимости без кэша, чтобы уменьшить размер слоя.
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONPATH=/app

# Команда по умолчанию, но в compose мы всё равно можем переопределять
CMD ["uvicorn", "src.webapp_app:app", "--host", "0.0.0.0", "--port", "8088", "--reload", "--reload-dir", "/app/src"]
