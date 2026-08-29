FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY api/pyproject.toml api/README.md ./api/
COPY api/src ./api/src
RUN pip install --no-cache-dir ./api
COPY taxii ./taxii
RUN useradd --create-home --uid 10002 taxii \
    && mkdir -p /data \
    && chown taxii:taxii /data
USER taxii
EXPOSE 9000
CMD ["python", "taxii/server.py", "--host", "0.0.0.0", "--port", "9000", "--data-file", "/data/objects.json", "--seed-data-file", "/app/taxii/data/objects.json"]
