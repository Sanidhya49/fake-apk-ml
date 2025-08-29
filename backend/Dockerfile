FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (libmagic for androguard compatibility if needed by shared libs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    unzip \
    libmagic1 \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Use monorepo root requirements (consolidated)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy only backend app
COPY backend/ ./backend
WORKDIR /app/backend

ENV DJANGO_SETTINGS_MODULE=fake_apk_backend.settings
EXPOSE 8000

CMD ["gunicorn", "fake_apk_backend.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2"]


