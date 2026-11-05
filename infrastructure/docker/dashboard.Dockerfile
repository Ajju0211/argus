# Dependency-free judge dashboard served by nginx.
# nginx proxies /api and /healthz to argus-api so the browser stays same-origin.

FROM nginx:1.27-alpine

COPY infrastructure/docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY apps/api/static/ /usr/share/nginx/html/

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
    CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1
