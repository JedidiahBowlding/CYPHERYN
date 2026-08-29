FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Pull fixed Debian security packages into the immutable release image instead
# of relying on the moving base tag to have been republished already.
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[dev]"
COPY tests ./tests

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data/quarantine /data/clamav-db \
    && chown -R appuser:appuser /data
USER appuser
EXPOSE 8000
CMD ["uvicorn", "intel_platform.main:app", "--host", "0.0.0.0", "--port", "8000"]
