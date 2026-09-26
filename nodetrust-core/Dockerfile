# Built and run on 26 Sep 2026 (compose up, healthcheck, demo, API from the host; the test suite passes
# inside this image). Base image pinned by index digest; bump tag and digest together (NT-044).
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 nodetrust
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY fixtures ./fixtures
RUN pip install --no-cache-dir . && mkdir -p /data && chown nodetrust /data
USER nodetrust
EXPOSE 8080
CMD ["nodetrust", "serve", "--host", "0.0.0.0", "--port", "8080", "--i-know-this-is-exposed"]
