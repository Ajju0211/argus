# ARGUS Lab B — Multi-Service Linux Host Evaluation Environment
FROM python:3.12-alpine

WORKDIR /lab
COPY server.py ./

ENV PYTHONUNBUFFERED=1 \
    LAB_B_HOST=0.0.0.0 \
    LAB_B_FTP_PORT=21 \
    LAB_B_SSH_PORT=22 \
    LAB_B_HTTP_PORT=8080

EXPOSE 21 22 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

CMD ["python", "server.py"]

