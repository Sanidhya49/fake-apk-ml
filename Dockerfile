FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps that help androguard (apk parsing), WeasyPrint (PDF generation), and compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    unzip \
    libmagic1 \
    ca-certificates \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libfontconfig1 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    libglib2.0-0 \
    libgobject-2.0-0 \
    libgirepository-1.0-1 \
    fonts-liberation \
    fonts-dejavu-core \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 9000

CMD ["uvicorn", "ml.infer_service:app", "--host", "0.0.0.0", "--port", "9000"]



