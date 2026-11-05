# syntax=docker/dockerfile:1.7
# DARKBYTE ARES API — production-oriented, non-root runtime image.
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system ares \
    && useradd --system --gid ares --create-home --home-dir /home/ares ares

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY engines ./engines
COPY integrations ./integrations
COPY plugins ./plugins
COPY reporting ./reporting
COPY scripts ./scripts

RUN mkdir -p /app/data/reports \
    && chown -R ares:ares /app

USER ares

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).read()"

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
