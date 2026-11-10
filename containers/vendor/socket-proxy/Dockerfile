# Tecnativa's maintained v0.5.0 release, pinned by digest. Update only the
# vulnerable Alpine libraries and preserve its entrypoint, HAProxy ACLs and env.
FROM ghcr.io/tecnativa/docker-socket-proxy@sha256:1f5038b54f06c3e18422902cf00ba21803d1c97805aae032e5e6673d532d3459

USER root
RUN apk add --no-cache --upgrade \
    libcrypto3=3.5.9-r0 \
    libssl3=3.5.9-r0 \
    pcre2=10.49-r0
