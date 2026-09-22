FROM python:3.11-slim

WORKDIR /app

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pii_service ./pii_service

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "pii_service.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
