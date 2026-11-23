FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r vibescan && useradd -r -g vibescan -d /app -s /sbin/nologin vibescan

WORKDIR /app

COPY pyproject.toml /app/pyproject.toml
COPY app /app/app

RUN pip install --upgrade pip && pip install . \
    && mkdir -p /app/data/uploads /app/data/reports \
    && chown -R vibescan:vibescan /app

USER vibescan

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
