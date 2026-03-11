# Contributing to OWASP Sentinel

Thank you for investing your time in contributing to OWASP Sentinel! We welcome all contributions — bug reports, documentation improvements, new features, and security feedback.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Branch Naming Conventions](#branch-naming-conventions)
5. [Commit Conventions](#commit-conventions)
6. [Pull Request Process](#pull-request-process)
7. [Code Style](#code-style)
8. [Testing Requirements](#testing-requirements)
9. [Documentation](#documentation)
10. [Release Process](#release-process)

---

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
By participating, you are expected to uphold this code. Please report unacceptable behaviour to **security@owasp-sentinel.io**.

---

## Getting Started

### Prerequisites

| Tool          | Minimum Version | Notes                          |
|---------------|-----------------|-------------------------------|
| Docker        | 24.x            | Required for all services     |
| Docker Compose| 2.x             | Bundled with Docker Desktop   |
| Python        | 3.11            | For local backend development |
| Node.js       | 20 LTS          | For local frontend development|
| Git           | 2.40+           | —                             |
| make          | 4.x             | Task runner                   |

### First-time Setup

```bash
# 1. Fork the repository on GitHub, then clone your fork
git clone https://github.com/<your-username>/owasp-sentinel.git
cd owasp-sentinel

# 2. Add the upstream remote
git remote add upstream https://github.com/owasp/owasp-sentinel.git

# 3. Create your .env from the example
make env

# 4. Install dev dependencies (Python + Node)
make dev-install

# 5. Start the full stack
make up

# 6. Apply database migrations
make migrate
```

The platform will be available at:

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000/docs
- **Traefik Dashboard**: http://localhost:8080
- **Flower**: http://localhost:5555
- **Grafana**: http://localhost:3001

---

## Development Setup

### Backend (FastAPI)

```bash
# Run locally without Docker (requires running postgres + redis)
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend (Next.js)

```bash
cd frontend
npm ci
npm run dev
```

### Database Migrations

```bash
# Create a new migration
make migrations MSG="add user preferences table"

# Apply migrations
make migrate

# Roll back one migration
make migrate-down
```

---

## Branch Naming Conventions

All branches **must** follow the pattern: `<type>/<short-description>`

| Type        | Use case                                  | Example                             |
|-------------|-------------------------------------------|-------------------------------------|
| `feat`      | New feature                               | `feat/nuclei-template-sync`         |
| `fix`       | Bug fix                                   | `fix/jwt-refresh-token-expiry`      |
| `docs`      | Documentation only                        | `docs/api-authentication-guide`     |
| `refactor`  | Code refactoring (no behaviour change)    | `refactor/scan-engine-abstraction`  |
| `test`      | Adding or updating tests                  | `test/celery-worker-unit-tests`     |
| `chore`     | Build, CI, dependency updates             | `chore/upgrade-fastapi-0-110`       |
| `security`  | Security hardening or vulnerability fix   | `security/sanitise-nuclei-input`    |
| `hotfix`    | Urgent production fix                     | `hotfix/critical-auth-bypass`       |

Branch names must use lowercase letters and hyphens only — **no spaces or underscores**.

---

## Commit Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.

### Format

```
<type>(<scope>): <short summary>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                                        |
|------------|----------------------------------------------------|
| `feat`     | A new feature                                      |
| `fix`      | A bug fix                                          |
| `docs`     | Documentation only changes                        |
| `style`    | Formatting, missing semicolons — no logic change  |
| `refactor` | Code change that neither fixes nor adds a feature |
| `perf`     | Performance improvement                            |
| `test`     | Adding or correcting tests                         |
| `build`    | Changes to build system or external dependencies  |
| `ci`       | Changes to CI/CD configuration                    |
| `chore`    | Other changes that don't modify src or test files |
| `revert`   | Reverts a previous commit                          |
| `security` | Security fix or hardening                          |

### Scopes

Use meaningful scopes from the project structure:
`auth`, `scans`, `reports`, `targets`, `users`, `notifications`, `worker`, `api`, `db`, `frontend`, `ci`, `docs`

### Examples

```
feat(scans): add Nuclei template auto-update scheduler

fix(auth): prevent JWT token reuse after logout

docs(api): add OpenAPI examples for scan endpoints

security(auth): enforce bcrypt cost factor ≥ 12

chore(ci): cache pip dependencies in GitHub Actions

BREAKING CHANGE: The scan result schema has been updated.
Clients must upgrade to API v3.
```

### Rules

- Summary line must be ≤ 72 characters
- Use the imperative mood: "add feature" not "added feature"
- Do not end the summary line with a period
- Reference issues at the footer: `Closes #123`, `Fixes #456`

---

## Pull Request Process

### Before Opening a PR

- [ ] Your branch is up to date with `main`: `git rebase upstream/main`
- [ ] All tests pass: `make test`
- [ ] Linting passes: `make lint`
- [ ] Migrations are included if schema changed: `make migrations MSG="..."`
- [ ] New features have tests with ≥ 80 % coverage for new code
- [ ] Documentation is updated if user-facing behaviour changed
- [ ] `CHANGELOG.md` entry added (if applicable)

### PR Title

PR titles must follow the same Conventional Commits format as commits.

### PR Description Template

When you open a PR, the template will guide you through:

1. **What** — A clear description of what was changed
2. **Why** — The motivation / problem being solved
3. **How** — Technical approach taken
4. **Testing** — How the change was tested
5. **Screenshots** — For UI changes
6. **Checklist** — Confirmation of quality gates

### Review Process

- At least **1 approval** from a code owner is required to merge
- All CI checks must pass (lint, test, build, security-scan)
- Address all review comments or mark them as resolved with justification
- Do not force-push after requesting review (use `git merge` to incorporate feedback)
- PRs are squash-merged into `main` to keep a clean history

---

## Code Style

### Python (Backend)

We use **ruff** for both linting and formatting (replaces flake8, black, isort).

```bash
# Format and fix
make format

# Check only
make lint-backend
```

Key rules enforced:

- Line length: **88 characters**
- Imports sorted with `isort` compatible rules (via ruff)
- Type annotations are **required** for all public functions
- Docstrings follow **Google style**
- No `# type: ignore` without an explanatory comment
- No bare `except:` — always specify the exception type

### TypeScript / JavaScript (Frontend)

We use **ESLint** with the Next.js recommended config and **Prettier** for formatting.

```bash
make lint-frontend
```

Key rules:

- Use `const` by default, `let` only when reassignment is needed
- Prefer named exports over default exports
- Async functions must handle errors explicitly
- No `any` type — use proper TypeScript types

### General

- Secrets **must never** be committed — use environment variables
- Log at appropriate levels (`DEBUG` for dev noise, `INFO` for milestones, `WARNING`/`ERROR` for problems)
- Keep functions small and focused (single responsibility)
- Prefer explicit over implicit

---

## Testing Requirements

### Backend

| Category         | Tool            | Requirement                              |
|------------------|-----------------|------------------------------------------|
| Unit tests       | pytest          | All business logic must be unit-tested   |
| Integration tests| pytest + httpx  | All API endpoints must be tested         |
| Async tests      | pytest-asyncio  | Use `@pytest.mark.asyncio`               |
| Coverage         | pytest-cov      | ≥ 80 % overall; 100 % for auth & security|
| Fixtures         | conftest.py     | Shared fixtures in `tests/conftest.py`   |

```bash
# Run with coverage
make test-backend

# Open HTML coverage report
open backend/htmlcov/index.html
```

Test structure:

```
backend/tests/
├── conftest.py           # Shared fixtures (DB, client, auth tokens)
├── unit/
│   ├── test_auth.py
│   ├── test_scans.py
│   └── test_reports.py
├── integration/
│   ├── test_api_auth.py
│   ├── test_api_scans.py
│   └── test_api_reports.py
└── e2e/
    └── test_full_scan_flow.py
```

### Frontend

```bash
make test-frontend
```

- Use **React Testing Library** for component tests
- Write tests alongside components in `__tests__/` directories
- Mock external API calls — never call the real API in tests

---

## Documentation

- All new API endpoints must have an **OpenAPI docstring** (FastAPI handles this automatically from Pydantic models + route docstrings)
- Complex business logic should have inline comments explaining *why*, not *what*
- Architecture decisions should be documented in `docs/adr/` (Architecture Decision Records)
- Update `README.md` if the development workflow changes

---

## Release Process

Releases follow [Semantic Versioning](https://semver.org/):

| Version bump | When to use                                         |
|--------------|-----------------------------------------------------|
| PATCH (x.y.Z)| Backwards-compatible bug fixes                      |
| MINOR (x.Y.z)| New backwards-compatible features                   |
| MAJOR (X.y.z)| Breaking API or schema changes                      |

Releases are automated via GitHub Actions when a tag is pushed:

```bash
git tag v3.1.0 -m "chore(release): v3.1.0"
git push upstream v3.1.0
```

---

## Questions?

- **GitHub Discussions**: For questions and ideas
- **GitHub Issues**: For bug reports and feature requests
- **Email**: contribute@owasp-sentinel.io

We appreciate every contribution, big and small. Thank you! 🛡️
