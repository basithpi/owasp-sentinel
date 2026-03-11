# Contributing to OWASP Sentinel

Thank you for your interest in contributing to **OWASP Sentinel v3 "Phantom Strike"**! This document explains how to get started, our workflow, and the standards we hold contributions to.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Fork & Clone](#fork--clone)
  - [Local Development Setup](#local-development-setup)
- [Development Workflow](#development-workflow)
  - [Branching Strategy](#branching-strategy)
  - [Making Changes](#making-changes)
  - [Commit Messages](#commit-messages)
  - [Pull Request Process](#pull-request-process)
- [Code Style](#code-style)
  - [Python (Backend)](#python-backend)
  - [TypeScript (Frontend)](#typescript-frontend)
- [Testing Requirements](#testing-requirements)
- [Documentation](#documentation)
- [Reporting Bugs](#reporting-bugs)
- [Proposing Features](#proposing-features)

---

## Code of Conduct

This project follows the [OWASP Code of Conduct](https://owasp.org/www-policy/operational/code-of-conduct). All contributors are expected to be respectful, inclusive, and professional. Harassment of any kind will not be tolerated.

---

## Getting Started

### Prerequisites

| Tool | Minimum Version |
|------|----------------|
| Docker | 24.x |
| Docker Compose | v2.20+ |
| Git | 2.40+ |
| Python | 3.12+ (for local dev without Docker) |
| Node.js | 20 LTS (for local dev without Docker) |
| Make | Any modern version |

### Fork & Clone

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/owasp-sentinel.git
   cd owasp-sentinel
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/basithpi/owasp-sentinel.git
   ```

### Local Development Setup

**Using Docker (recommended):**

```bash
# Copy and configure the environment file
make env
# Edit .env with your local values — pay particular attention to SECRET_KEY
nano .env

# Build images and start all services
make build
make up

# Apply database migrations and seed sample data
make migrate
make seed
```

The application will be available at:

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| MinIO Console | http://localhost:9001 |
| Grafana | http://localhost:3001 |
| Meilisearch | http://localhost:7700 |

**Without Docker (advanced):**

```bash
# Backend
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements/dev.txt
cp ../.env.example .env   # edit as needed
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

---

## Development Workflow

### Branching Strategy

We follow a simplified **GitHub Flow**:

| Branch | Purpose |
|--------|---------|
| `main` | Production-ready code. Protected; requires PR + passing CI. |
| `develop` | Integration branch for upcoming release. Target PRs here. |
| `feature/<slug>` | New features |
| `fix/<slug>` | Bug fixes |
| `chore/<slug>` | Refactors, dependency updates, tooling |
| `docs/<slug>` | Documentation-only changes |

Always branch off `develop`:

```bash
git fetch upstream
git checkout develop
git pull upstream develop
git checkout -b feature/my-awesome-feature
```

### Making Changes

- Keep PRs focused: one logical change per PR.
- Add or update tests for every code change.
- Update `CHANGELOG.md` under the `[Unreleased]` section.
- Run `make check` (lint + type check) before pushing.

### Commit Messages

We use the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <short summary>

[optional body]

[optional footer(s)]
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `revert`

Examples:
```
feat(reports): add PDF export with CVSS scoring
fix(auth): prevent JWT refresh token reuse
docs(api): document /vulnerabilities endpoint
chore(deps): upgrade FastAPI to 0.115
```

- Use the imperative mood ("add" not "added").
- Keep the summary under 72 characters.
- Reference issues/PRs in the footer: `Closes #42`, `Refs #101`.

### Pull Request Process

1. Push your branch to your fork:
   ```bash
   git push origin feature/my-awesome-feature
   ```
2. Open a PR against `develop` on the upstream repository.
3. Fill in the PR template completely (description, testing steps, screenshots if UI change).
4. Ensure all CI checks pass — the PR cannot be merged with failing checks.
5. Request a review from at least one maintainer.
6. Address review feedback promptly.
7. A maintainer will squash-merge your PR once approved.

---

## Code Style

### Python (Backend)

- **Formatter:** [Black](https://black.readthedocs.io/) with default settings (line length 88).
- **Linter:** [Ruff](https://docs.astral.sh/ruff/) — config lives in `backend/pyproject.toml`.
- **Type hints:** All public functions and methods **must** have full type annotations. We run `mypy --strict`.
- **Docstrings:** [Google style](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) for all public APIs.

```bash
# Auto-fix and format
make fmt

# Check only (CI mode)
make lint
make typecheck
```

### TypeScript (Frontend)

- **Formatter / Linter:** ESLint + Prettier — config in `frontend/.eslintrc.json` and `frontend/.prettierrc`.
- **Imports:** Absolute imports via `@/` alias (mapped to `frontend/src/`).
- **Components:** Functional components with explicit prop types. No `any`.
- **Naming:** PascalCase for components, camelCase for functions/variables, UPPER_SNAKE_CASE for constants.

```bash
# Lint frontend
make lint-frontend

# Type-check frontend
make typecheck-frontend
```

---

## Testing Requirements

All code changes must include appropriate tests.

### Backend

| Test type | Framework | Location |
|-----------|-----------|----------|
| Unit | pytest | `backend/tests/unit/` |
| Integration | pytest | `backend/tests/integration/` |
| API (E2E) | pytest + httpx | `backend/tests/api/` |

- Minimum coverage requirement: **80%** for new code (enforced by CI).
- Use fixtures in `backend/tests/conftest.py` for shared state.
- Mark slow/external tests with `@pytest.mark.slow` or `@pytest.mark.integration`.

```bash
make test              # Full suite
make test-fast         # Unit tests only
make test-coverage     # Generate HTML coverage report
```

### Frontend

- Unit/component tests with **Vitest** + **Testing Library** (`frontend/src/__tests__/`).
- E2E tests with **Playwright** (`frontend/e2e/`).
- Snapshot updates must be intentional: `npm run test -- -u`.

```bash
make test-frontend
```

---

## Documentation

- Update the relevant section of `README.md` for user-visible changes.
- New API endpoints must include OpenAPI docstrings (`summary`, `description`, `response_model`).
- Complex internal logic should have inline comments explaining *why*, not *what*.
- Architecture decision records go in `docs/adr/`.

---

## Reporting Bugs

Please use the [Bug Report issue template](.github/ISSUE_TEMPLATE/bug_report.md) and include:

- Steps to reproduce (minimal, reproducible example preferred).
- Expected vs. actual behaviour.
- Environment details (OS, Docker version, browser).
- Relevant logs (`make logs-backend`).

**Security bugs:** See [SECURITY.md](SECURITY.md) — do **not** open a public GitHub issue.

---

## Proposing Features

Open a [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md) issue first to discuss the idea before investing time building it. Large features benefit from an Architecture Decision Record (`docs/adr/`) to align on design before implementation.
