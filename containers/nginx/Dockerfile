# ===================================================
# SCYTHE Nginx Container — Security Hardened
# Receptionist: routes REST API + WebSocket traffic
# to the Backend (Uvicorn) container.
#
# TLS: generates a self-signed cert at runtime for
# local use. In production, mount real certs from
# Let's Encrypt (or your CA) over /etc/nginx/certs/.
# ===================================================

FROM nginx:stable-alpine@sha256:ed84151ed2d47ef93c0939eb9b9754c6990db6092cd2081e11988a47a83d47ea

# curl: needed for HEALTHCHECK
# openssl: needed to generate self-signed TLS cert
RUN apk upgrade --no-cache && apk add --no-cache curl openssl

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Create directory for TLS certificates
RUN mkdir -p /etc/nginx/certs

# Install dynamic cert generation script into docker-entrypoint.d so nginx
# generates a unique self-signed cert on container start (if none mounted)
# instead of baking a private key into the built image layers.
COPY generate-ssl.sh /docker-entrypoint.d/99-generate-ssl.sh
RUN chmod +x /docker-entrypoint.d/99-generate-ssl.sh

# Copy our hardened config
COPY nginx.conf /etc/nginx/nginx.conf

COPY configure-runtime.sh /docker-entrypoint.d/98-configure-runtime.sh
RUN chmod +x /docker-entrypoint.d/98-configure-runtime.sh

EXPOSE 80 443
CMD ["nginx", "-c", "/tmp/scythe-nginx.conf", "-g", "daemon off;"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsk https://localhost/health || exit 1
