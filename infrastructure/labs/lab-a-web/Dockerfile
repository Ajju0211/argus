# ARGUS Lab A — Apache 2.4.49 Mock Evaluation Environment
FROM python:3.12-alpine

WORKDIR /lab
COPY server.py ./

ENV PYTHONUNBUFFERED=1 \
    LAB_A_HOST=0.0.0.0 \
    LAB_A_PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

CMD ["python", "server.py"]

