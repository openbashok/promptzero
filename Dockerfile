# syntax=docker/dockerfile:1.7

# =====================================================================
# PromptZero — Dockerfile
# ---------------------------------------------------------------------
# Multi-stage build. The builder installs every Python dependency and
# downloads the spaCy NLP models into a self-contained virtualenv at
# /opt/venv. The runtime stage just copies that venv plus the proxy
# source, drops privileges to a non-root user and starts uvicorn.
#
#   docker run -p 8000:8000 -e ANTHROPIC_API_KEY=sk-ant-... \
#     ghcr.io/openbashok/promptzero
#
# Override the spaCy model size with --build-arg SPACY_SIZE=md|sm to
# produce a lighter image (default 'lg' is best accuracy ~1.5 GB; 'sm'
# lands around 300 MB).
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

# Use a self-contained virtualenv so the runtime stage can copy a
# single directory and have everything (deps + spaCy models) in place.
# This avoids the `pip install --user` foot-gun where `spacy download`
# installs models to global site-packages instead of /root/.local.
ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /build
COPY requirements.txt .
RUN pip install -r requirements.txt

# Download both spaCy NLP models — bundled inside the venv so the
# first request doesn't pay the model download cost at runtime.
RUN python -m spacy download "en_core_web_${SPACY_SIZE}" \
 && python -m spacy download "es_core_news_${SPACY_SIZE}"


# ---------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    RELOAD=false

# curl is used by the HEALTHCHECK below.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

# Non-root user — the proxy doesn't need elevated privileges.
RUN useradd --create-home --shell /bin/bash promptzero

# Bring the virtualenv (deps + spaCy models) from the builder.
COPY --from=builder --chown=promptzero:promptzero /opt/venv /opt/venv

USER promptzero
WORKDIR /home/promptzero

# Proxy source.
COPY --chown=promptzero:promptzero main.py sanitizer.py ./

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fs http://localhost:8000/health >/dev/null || exit 1

CMD ["python", "main.py"]
