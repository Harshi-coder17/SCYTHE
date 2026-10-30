#!/bin/sh
set -eu
port="${NGINX_HTTPS_PORT:-443}"
case "$port" in ''|*[!0-9]*) echo 'NGINX_HTTPS_PORT must be numeric' >&2; exit 1;; esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo 'NGINX_HTTPS_PORT must be between 1 and 65535' >&2
    exit 1
fi
SCYTHE_HTTPS_PORT_SUFFIX=":$port"
if [ "$port" -eq 443 ]; then SCYTHE_HTTPS_PORT_SUFFIX=''; fi
export SCYTHE_HTTPS_PORT_SUFFIX
# Restrict substitution to our port suffix; preserve nginx's own $variables.
envsubst '${SCYTHE_HTTPS_PORT_SUFFIX}' < /etc/nginx/nginx.conf > /tmp/scythe-nginx.conf
