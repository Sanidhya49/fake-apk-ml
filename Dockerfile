FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=9000 \
    FLASK_DEBUG=false

WORKDIR /app

# System deps that help androguard (apk parsing) and compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    unzip \
    libmagic1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt flask_requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r flask_requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p artifacts/static_jsons models

EXPOSE 9000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:9000/', timeout=5)" || exit 1

# Default to Flask app, but can be overridden
CMD ["python", "flask_app/main.py"]



