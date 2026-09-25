# NOT yet built/verified (Docker unavailable offline on the dev machine). Pin the base image
# by digest before release (NT-044 provenance).
FROM python:3.12-slim

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
