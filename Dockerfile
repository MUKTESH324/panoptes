FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml requirements.txt README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 argus
USER argus

ENTRYPOINT ["argus"]
CMD ["--help"]
