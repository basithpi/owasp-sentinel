# OWASP Sentinel v3 — Phantom Strike

<div align="center">

[![CI](https://github.com/basithpi/owasp-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/basithpi/owasp-sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0.0--phantom--strike-blueviolet)](https://github.com/basithpi/owasp-sentinel/releases)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-15-black?logo=next.js)](https://nextjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)](docker-compose.yml)
[![OWASP](https://img.shields.io/badge/OWASP-Project-blue)](https://owasp.org)

**A production-grade bug bounty platform built for security researchers and enterprise teams.**

[Quick Start](#quick-start) · [Features](#features) · [Architecture](#architecture) · [API Docs](#api-documentation) · [Contributing](CONTRIBUTING.md)

</div>

---

## Overview

**OWASP Sentinel v3 "Phantom Strike"** is an open-source, self-hosted bug bounty and vulnerability disclosure platform designed with security researchers, red teams, and enterprise security operations in mind.

Phantom Strike brings intelligent triage powered by LLMs, OWASP Top 10 alignment, automated re-testing pipelines, and deep integration with industry-standard tools — all in a single deployable stack.

---

## Features

### 🎯 Core Platform
- **Multi-program support** — run unlimited public and private bug bounty programs simultaneously
- **Role-based access control** — Researcher / Triager / Program Manager / Admin roles with fine-grained permissions
- **Full audit trail** — every state change, comment, and payout is immutably logged
- **Customisable reward structures** — fixed, range, or CVSS-based bounty calculations

### 🤖 AI-Powered Triage
- **Automatic severity scoring** — GPT-4o and Claude 3.5 Sonnet ensemble for CVSS estimation
- **Duplicate detection** — semantic similarity search via Meilisearch + embeddings
- **Smart deduplication** — clusters related reports across programs automatically
- **LLM-assisted writeup generation** — researchers get structured templates; triagers get AI summaries

### 🔍 Scanner Integration
- **Nuclei** — template-based scanning with custom template library
- **InteractSH** — out-of-band interaction tracking for SSRF / blind injection
- **FFUF** — fuzzing integration for authenticated endpoints
- **Subfinder / HTTPX** — attack surface management
- **Custom webhook scan results** — ingest findings from any scanner via REST

### 📊 Analytics & Reporting
- **Real-time dashboards** — Grafana with pre-built vulnerability trend dashboards
- **OWASP Top 10 heatmaps** — visual breakdown of your exposure
- **SLA tracking** — time-to-triage and time-to-fix metrics per program
- **PDF report export** — executive-ready vulnerability reports with CVSS detail
- **CVE/CWE mapping** — automatic linking to NVD and CWE databases

### 🛡️ Security Operations
- **Findings timeline** — chronological view of vulnerability discovery across the organisation
- **Retest workflows** — assign retests to researchers; track verification status
- **VDP (Vulnerability Disclosure Policy) page** — public-facing `security.txt` + HTML page generation
- **Integrations** — Jira, GitHub Issues, Slack, Discord, PagerDuty webhooks

---

## Architecture

```
                           ┌─────────────────────────────────────────┐
                           │            Internet / Users              │
                           └────────────────┬────────────────────────┘
                                            │ HTTPS (443)
                           ┌────────────────▼────────────────────────┐
                           │         Traefik v3 (Reverse Proxy)      │
                           │   TLS termination · Rate limiting        │
                           └──┬──────────┬──────────┬────────────────┘
                              │          │          │
               ┌──────────────▼──┐  ┌───▼──────┐  ┌▼──────────────────┐
               │  Next.js 15     │  │ FastAPI  │  │  MinIO            │
               │  Frontend       │  │ Backend  │  │  Object Storage   │
               │  :3000          │  │  :8000   │  │  :9000            │
               └─────────────────┘  └────┬─────┘  └───────────────────┘
                                         │
              ┌──────────────────────────┼────────────────────────────┐
              │                          │                            │
   ┌──────────▼──────┐    ┌─────────────▼──────┐    ┌───────────────▼───┐
   │  PostgreSQL 16  │    │   Redis 7           │    │  Meilisearch v1.6 │
   │  Primary DB     │    │   Cache · Sessions  │    │  Full-text Search │
   │  :5432          │    │   Celery Broker     │    │  :7700            │
   └─────────────────┘    └─────────────────────┘    └───────────────────┘
                                    │
              ┌─────────────────────┼────────────────────────────────┐
              │                     │                                │
   ┌──────────▼──────┐  ┌──────────▼────────┐  ┌────────────────────▼──┐
   │  Celery Worker  │  │  Celery Beat       │  │  InteractSH Server    │
   │  Async tasks    │  │  Scheduled jobs    │  │  OOB interactions     │
   │  (4 queues)     │  │                    │  │  :1094                │
   └─────────────────┘  └────────────────────┘  └───────────────────────┘
                                    │
              ┌─────────────────────┴───────────────────────────────┐
              │                                                      │
   ┌──────────▼──────────┐                        ┌────────────────▼──┐
   │  Prometheus          │                        │  Grafana          │
   │  Metrics scraping    │◄───────────────────────│  Dashboards       │
   │  :9090               │                        │  :3001            │
   └──────────────────────┘                        └───────────────────┘
```

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) ≥ 24.x with [Compose v2](https://docs.docker.com/compose/install/)
- 4 GB RAM minimum (8 GB recommended for AI features)
- Ports 80, 443, 8000, 3000 available on the host

### 1. Clone the repository

```bash
git clone https://github.com/basithpi/owasp-sentinel.git
cd owasp-sentinel
```

### 2. Configure environment

```bash
cp .env.example .env
# Open .env in your editor and set all required values,
# especially SECRET_KEY, POSTGRES_PASSWORD, and REDIS_PASSWORD.
nano .env
```

### 3. Start the stack

```bash
make build   # Build all images (~5 min on first run)
make up      # Start all services in detached mode
make migrate # Apply database migrations
make seed    # Load initial data (admin user, sample programs)
```

### 4. Open the application

| Service | URL | Default credentials |
|---------|-----|---------------------|
| Frontend | http://localhost:3000 | admin / changeme *(change immediately)* |
| API Docs | http://localhost:8000/docs | — |
| Grafana | http://localhost:3001 | admin / changeme |
| MinIO Console | http://localhost:9001 | minioadmin / changeme123 |

> **⚠️ Change all default passwords before exposing to any network.**

---

## Development Setup

For a full developer environment with hot-reload:

```bash
# 1. Start infrastructure services only
docker compose up -d postgres redis minio meilisearch

# 2. Backend (with reload)
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements/dev.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# 3. Frontend (separate terminal, with HMR)
cd frontend
npm install
npm run dev
```

Useful developer commands:

```bash
make shell           # bash inside backend container
make shell-db        # psql inside postgres container
make logs            # tail all service logs
make test            # run backend pytest suite
make lint            # ruff + black check
make typecheck       # mypy static analysis
make fmt             # auto-format all Python code
make test-coverage   # pytest + HTML coverage report
```

---

## API Documentation

Interactive API documentation is available at runtime:

| Format | URL |
|--------|-----|
| Swagger UI | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |
| OpenAPI JSON | http://localhost:8000/openapi.json |

Key endpoint groups:

| Prefix | Description |
|--------|-------------|
| `/api/v1/auth` | Authentication (login, register, token refresh, OAuth) |
| `/api/v1/programs` | Bug bounty program CRUD |
| `/api/v1/reports` | Vulnerability report submission and management |
| `/api/v1/vulnerabilities` | Vulnerability database with CVSS scoring |
| `/api/v1/payouts` | Reward management and payout processing |
| `/api/v1/users` | User profiles and settings |
| `/api/v1/scans` | Automated scan jobs and results |
| `/api/v1/search` | Full-text search across reports and vulnerabilities |
| `/api/v1/webhooks` | Incoming/outgoing webhook management |
| `/api/v1/admin` | Platform administration |

---

## Screenshots

> Screenshots will be added as the UI is developed.

| Dashboard | Report Detail | Analytics |
|-----------|--------------|-----------|
| *(coming soon)* | *(coming soon)* | *(coming soon)* |

---

## Project Structure

```
owasp-sentinel/
├── backend/                 # Python FastAPI application
│   ├── app/
│   │   ├── api/             # Route handlers (v1/)
│   │   ├── core/            # Config, security, database
│   │   ├── models/          # SQLAlchemy ORM models
│   │   ├── schemas/         # Pydantic request/response schemas
│   │   ├── services/        # Business logic layer
│   │   ├── tasks/           # Celery tasks
│   │   └── main.py          # FastAPI application factory
│   ├── alembic/             # Database migrations
│   ├── tests/               # pytest test suite
│   └── requirements/        # Pinned dependencies
├── frontend/                # Next.js 15 application
│   ├── src/
│   │   ├── app/             # App Router pages & layouts
│   │   ├── components/      # Reusable React components
│   │   ├── hooks/           # Custom React hooks
│   │   ├── lib/             # API client, utilities
│   │   └── types/           # TypeScript type definitions
│   └── public/              # Static assets
├── monitoring/              # Prometheus & Grafana config
├── scripts/                 # Init scripts, seed data
├── docs/                    # Architecture docs, ADRs
├── docker-compose.yml       # Full production stack
├── Makefile                 # Developer convenience commands
└── .github/workflows/       # CI/CD pipelines
```

---

## Security

Please review our [Security Policy](SECURITY.md) before reporting vulnerabilities.

- Do **not** open public GitHub issues for security bugs.
- Use [GitHub Security Advisories](https://github.com/basithpi/owasp-sentinel/security/advisories) for responsible disclosure.
- We target a **48-hour** acknowledgement and **14-day** fix for critical issues.

---

## Contributing

We welcome contributions from the security community! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for:

- How to set up your local development environment
- Branching strategy and commit message conventions
- Code style requirements (ruff, black, mypy, ESLint)
- Testing requirements (minimum 80% coverage)
- PR review process

---

## License

[MIT](LICENSE) © 2025 [basithpi](https://github.com/basithpi)

---

<div align="center">

Built with ❤️ by the security community, for the security community.

*OWASP Sentinel is not an official OWASP project.*

</div>