# =============================================================================
# OWASP Sentinel v3 - Backend Dockerfile
# =============================================================================
# Multi-stage build:
#   Stage 1 (builder)    - install Python deps into a prefix
#   Stage 2 (tools)      - download and install security scanning tools
#   Stage 3 (production) - minimal runtime image
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: builder — compile Python wheels
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libffi-dev \
        libssl-dev \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

# Create a virtual environment in /opt/venv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install wheel first for faster builds
RUN pip install --upgrade pip wheel

# Copy and install Python dependencies (leverages layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: tools — download and install security scanning binaries
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS tools

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        wget \
        ca-certificates \
        unzip \
        tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

# nuclei — fast vulnerability scanner
ARG NUCLEI_VERSION=3.2.4
RUN curl -sSL \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
        -o nuclei.zip \
    && unzip nuclei.zip nuclei \
    && chmod +x nuclei \
    && rm nuclei.zip

# subfinder — subdomain discovery
ARG SUBFINDER_VERSION=2.6.3
RUN curl -sSL \
        "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
        -o subfinder.zip \
    && unzip subfinder.zip subfinder \
    && chmod +x subfinder \
    && rm subfinder.zip

# httpx — HTTP probing
ARG HTTPX_VERSION=1.3.7
RUN curl -sSL \
        "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" \
        -o httpx.zip \
    && unzip httpx.zip httpx \
    && chmod +x httpx \
    && rm httpx.zip

# dnsx — DNS toolkit
ARG DNSX_VERSION=1.1.6
RUN curl -sSL \
        "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_amd64.zip" \
        -o dnsx.zip \
    && unzip dnsx.zip dnsx \
    && chmod +x dnsx \
    && rm dnsx.zip

# naabu — port scanner
ARG NAABU_VERSION=2.3.1
RUN curl -sSL \
        "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip" \
        -o naabu.zip \
    && unzip naabu.zip naabu \
    && chmod +x naabu \
    && rm naabu.zip

# katana — web crawler
ARG KATANA_VERSION=1.0.5
RUN curl -sSL \
        "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip" \
        -o katana.zip \
    && unzip katana.zip katana \
    && chmod +x katana \
    && rm katana.zip

# -----------------------------------------------------------------------------
# Stage 3: production — slim runtime image
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS production

LABEL org.opencontainers.image.title="OWASP Sentinel Backend" \
      org.opencontainers.image.description="FastAPI backend for OWASP Sentinel v3" \
      org.opencontainers.image.version="3.0.0" \
      org.opencontainers.image.licenses="MIT"

# Install runtime OS dependencies (nmap requires apt; others are static binaries)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        ca-certificates \
        libpq5 \
        libmagic1 \
        wget \
        git \
        libffi8 \
        libssl3 \
        # WeasyPrint runtime deps
        libgobject-2.0-0 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libcairo2 \
        libgdk-pixbuf2.0-0 \
        libffi-dev \
        shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Copy the virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy security tool binaries from tools stage
COPY --from=tools /tools/nuclei      /usr/local/bin/nuclei
COPY --from=tools /tools/subfinder   /usr/local/bin/subfinder
COPY --from=tools /tools/httpx       /usr/local/bin/httpx
COPY --from=tools /tools/dnsx        /usr/local/bin/dnsx
COPY --from=tools /tools/naabu       /usr/local/bin/naabu
COPY --from=tools /tools/katana      /usr/local/bin/katana

# Activate venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

# Create non-root user for running the application
RUN groupadd --gid 1001 sentinel \
    && useradd --uid 1001 --gid sentinel --shell /bin/bash --create-home sentinel

# Create required directories and set ownership
RUN mkdir -p /app /app/uploads /app/reports /app/nuclei-templates /app/logs \
    && chown -R sentinel:sentinel /app

WORKDIR /app

# Copy application source
COPY --chown=sentinel:sentinel . .

# Update nuclei templates (best-effort; skip if no network during build)
RUN nuclei -update-templates -silent 2>/dev/null || true

USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
