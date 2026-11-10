# ===================================================
# SCYTHE Backend Container
# Stage 1: Build deps (cached layer)
# Stage 2: Runtime image — non-root, hardened
# ===================================================

# --- Build stage: install Python deps ---
FROM python:3.11-slim@sha256:b7a9e5f6a93d6d4a31f129bbd4bdee69efccb6ded0fb230d78aafaf37af98377 AS builder

WORKDIR /app

# System build deps
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# --- Runtime stage: minimal, non-root ---
FROM python:3.11-slim@sha256:b7a9e5f6a93d6d4a31f129bbd4bdee69efccb6ded0fb230d78aafaf37af98377 AS runtime

# Security: non-root user
RUN groupadd --gid 10001 scythe \
    && useradd --uid 10001 --gid scythe --shell /bin/bash --create-home scythe

WORKDIR /app

# Runtime system deps only — docker-cli removed, this image never
# talks to docker_socket_proxy (only celery_worker does — see
# backend/Dockerfile.worker)
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    libpq5 libgomp1 gosu \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local
RUN python -m pip install --no-cache-dir --upgrade pip==26.2.1 setuptools==84.0.0 wheel==0.48.0 \
    && python -m pip uninstall -y pip

# Copy application source
COPY --chown=scythe:scythe . .

# Ensure app, shared, and backup directories exist with read/write permissions for scythe user
RUN mkdir -p /app /shared/scans /backups /app/models /app/celerybeat-schedule \
    && chown -R scythe:scythe /app /shared /backups \
    && chmod -R 0775 /app /shared /backups
VOLUME ["/shared/scans"]

COPY --chown=scythe:scythe entrypoint.sh /app/entrypoint.sh
COPY --chown=scythe:scythe celery_entrypoint.sh /app/celery_entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/celery_entrypoint.sh

USER scythe

EXPOSE 8000

# Health check — hits the root endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=5)"]

# entrypoint: waits for Postgres, runs db init, then execs CMD
ENTRYPOINT ["/app/entrypoint.sh"]
# Only Docker-private peers may supply proxy headers. Nginx overwrites X-Forwarded-For
# with the socket peer address, so client-supplied chains are never trusted.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--log-level", "info", "--proxy-headers", "--forwarded-allow-ips=172.24.0.10"]
