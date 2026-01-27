# Базовый образ с Python, чтобы сборка была компактной и предсказуемой.
FROM python:3.11-slim

# Рабочая директория приложения внутри контейнера.
WORKDIR /app

# Сначала копируем зависимости, чтобы использовать Docker cache.
COPY requirements.txt ./
# Устанавливаем зависимости без кэша, чтобы уменьшить размер слоя.
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходники приложения.
COPY src ./src

# Добавляем PYTHONPATH для корректного импорта модулей.
ENV PYTHONPATH=/app

# Запускаем веб-приложение на нестандартном порту 8088.
CMD ["uvicorn", "src.webapp_app:app", "--host", "0.0.0.0", "--port", "8088"]
