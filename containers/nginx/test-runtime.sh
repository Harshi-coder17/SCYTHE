#!/bin/sh
set -eu
# Run with nginx.conf at /etc/nginx/nginx.conf and configure-runtime.sh beside
# this script. No server or backend connection is required for these checks.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for port in 0 65536 invalid; do
    if NGINX_HTTPS_PORT="$port" sh "$script_dir/configure-runtime.sh"; then
        echo "Invalid port accepted: $port" >&2
        exit 1
    fi
done
NGINX_HTTPS_PORT=443 sh "$script_dir/configure-runtime.sh"
grep -F 'https://$host$request_uri' /tmp/scythe-nginx.conf
NGINX_HTTPS_PORT=8443 sh "$script_dir/configure-runtime.sh"
grep -F 'https://$host:8443$request_uri' /tmp/scythe-nginx.conf
grep -F 'map $http_upgrade $connection_upgrade' /tmp/scythe-nginx.conf
echo 'Nginx port validation and restricted variable substitution passed.'
