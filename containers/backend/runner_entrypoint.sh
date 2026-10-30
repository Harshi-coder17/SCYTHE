#!/bin/bash
set -e

# Privilege drop / non-root enforcement:
# Ensure we do not execute as root. If running as root, drop privileges to scythe.
if [ "$(id -u)" = "0" ]; then
    echo "[runner-entrypoint] Running as root; dropping privileges to scythe..."
    if command -v gosu >/dev/null 2>&1; then
        exec gosu scythe "$0" "$@"
    elif command -v su-exec >/dev/null 2>&1; then
        exec su-exec scythe "$0" "$@"
    elif command -v runuser >/dev/null 2>&1; then
        exec runuser -u scythe -- "$0" "$@"
    else
        exec su -s /bin/bash scythe -c "\"$0\" \"\$@\"" -- "$@"
    fi
fi

# The docker_socket_proxy service (Tecnativa) ignores Basic Auth.
# Security is provided by network isolation (docker_proxy_net).
# Point DOCKER_HOST directly to the proxy instead of using an HAProxy sidecar.
export DOCKER_HOST="tcp://docker_socket_proxy:2375"

# Start the actual sandbox runner service
exec python /app/sandbox_runner_svc.py
