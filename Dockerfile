# syntax=docker/dockerfile:1.7

# =====================================================================
# PromptZero — Dockerfile
# ---------------------------------------------------------------------
# Multi-stage build: a fat builder with all the toolchain we need to
# install Presidio / spaCy and download the NLP models, and a slim
# runtime that only carries the Python packages, the models, and the
# proxy source.
#
#   docker build -t promptzero .
#   docker run -p 8000:8000 -e ANTHROPIC_API_KEY=sk-ant-... promptzero
#
# Override the spaCy model size with --build-arg SPACY_SIZE=md|sm to
# produce a lighter image (the default 'lg' is best accuracy but the
# image lands around 1.5 GB; 'sm' lands around 300 MB).
# =====================================================================


# ---------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------
FROM python:3.12-slim AS builder

ARG SPACY_SIZE=lg

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System packages required to compile a couple of Python wheels
# (spaCy/blis) that don't always ship manylinux wheels for slim images.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt .
RUN pip install --user --no-warn-script-location -r requirements.txt

# Download both spaCy NLP models — bundled in the final image so the
# first request doesn't pay the model download cost.
RUN python -m spacy download "en_core_web_${SPACY_SIZE}" \
 && python -m spacy download "es_core_news_${SPACY_SIZE}"


# ---------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/promptzero/.local/bin:$PATH

# curl is used by the HEALTHCHECK below.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

# Non-root user — the proxy doesn't need elevated privileges.
RUN useradd --create-home --shell /bin/bash promptzero
USER promptzero
WORKDIR /home/promptzero

# Bring over the Python packages and spaCy models from the builder.
COPY --from=builder --chown=promptzero:promptzero /root/.local /home/promptzero/.local

# Proxy source.
COPY --chown=promptzero:promptzero main.py sanitizer.py ./

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fs http://localhost:8000/health >/dev/null || exit 1

CMD ["python", "main.py"]
