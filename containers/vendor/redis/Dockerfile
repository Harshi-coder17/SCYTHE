# Redis 7.2 stays on its existing Alpine 3.21 base. Apply the fixed OpenSSL
# packages for CVE-2026-84782 without changing Redis configuration or entrypoint.
FROM redis@sha256:29e8589c3f9ba699b5f7aa4b3c7733c58852a3626439e619aa0ee78de08c6ca0

USER root
RUN apk add --no-cache --upgrade \
    libcrypto3=3.3.7-r2 \
    libssl3=3.3.7-r2
