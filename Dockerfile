FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 appuser

COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

COPY --chown=appuser:appuser src/ /app/src/
COPY --chown=appuser:appuser alembic.ini .env.example README.md ./

RUN mkdir -p /app/data && chown -R appuser:appuser /app/data

USER appuser

EXPOSE 8000

CMD ["uvicorn", "tbhm.main:app", "--host", "0.0.0.0", "--port", "8000"]