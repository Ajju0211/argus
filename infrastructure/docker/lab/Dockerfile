# Minimal authorized lab container for the compose demo.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /lab
COPY infrastructure/docker/lab/lab.py ./lab.py

RUN useradd -m -u 1000 lab
USER lab

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=6 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"

CMD ["python", "lab.py"]
