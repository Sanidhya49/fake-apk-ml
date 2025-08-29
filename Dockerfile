FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps that help androguard (apk parsing) and compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    unzip \
    libmagic1 \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 9000

CMD ["uvicorn", "ml.infer_service:app", "--host", "0.0.0.0", "--port", "9000"]



