# =============================================================================
# OWASP Sentinel v3 - Makefile
# =============================================================================

.DEFAULT_GOAL := help
SHELL         := /bin/bash
COMPOSE       := docker compose
BACKEND_SVC   := backend
FRONTEND_SVC  := frontend
PYTHON        := python3
PIP           := pip3

# Colours
CYAN  := \033[0;36m
GREEN := \033[0;32m
RESET := \033[0m

.PHONY: help
help: ## Show this help message
	@echo ""
	@echo "  $(CYAN)OWASP Sentinel v3$(RESET) - Available commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}'
	@echo ""

# =============================================================================
# Installation
# =============================================================================

.PHONY: install
install: ## Install production Python dependencies
	$(PIP) install --upgrade pip
	$(PIP) install -r backend/requirements.txt

.PHONY: dev-install
dev-install: ## Install development Python dependencies (includes test/lint tools)
	$(PIP) install --upgrade pip
	$(PIP) install -r backend/requirements.txt
	$(PIP) install ruff mypy pytest pytest-asyncio pytest-cov httpx anyio
	@if [ -f frontend/package.json ]; then cd frontend && npm ci; fi
	@echo "$(GREEN)Dev dependencies installed$(RESET)"

# =============================================================================
# Docker Compose Lifecycle
# =============================================================================

.PHONY: up
up: ## Start all services in detached mode
	$(COMPOSE) up -d
	@echo "$(GREEN)All services started$(RESET)"
	@echo "  Backend:      http://localhost:8000"
	@echo "  Frontend:     http://localhost:3000"
	@echo "  Traefik:      http://localhost:8080"
	@echo "  Flower:       http://localhost:5555"
	@echo "  Grafana:      http://localhost:3001"
	@echo "  Prometheus:   http://localhost:9090"
	@echo "  MinIO:        http://localhost:9001"
	@echo "  Meilisearch:  http://localhost:7700"

.PHONY: down
down: ## Stop and remove all containers
	$(COMPOSE) down --remove-orphans
	@echo "$(GREEN)All services stopped$(RESET)"

.PHONY: restart
restart: down up ## Restart all services

.PHONY: logs
logs: ## Tail logs for all services (Ctrl+C to exit)
	$(COMPOSE) logs -f

.PHONY: logs-backend
logs-backend: ## Tail backend service logs
	$(COMPOSE) logs -f $(BACKEND_SVC)

.PHONY: logs-worker
logs-worker: ## Tail celery-worker service logs
	$(COMPOSE) logs -f celery-worker

.PHONY: ps
ps: ## Show running container status
	$(COMPOSE) ps

# =============================================================================
# Build
# =============================================================================

.PHONY: build
build: ## Build all Docker images (no cache)
	$(COMPOSE) build --no-cache
	@echo "$(GREEN)All images built$(RESET)"

.PHONY: build-backend
build-backend: ## Build backend Docker image only
	$(COMPOSE) build --no-cache $(BACKEND_SVC)
	@echo "$(GREEN)Backend image built$(RESET)"

.PHONY: build-frontend
build-frontend: ## Build frontend Docker image only
	$(COMPOSE) build --no-cache $(FRONTEND_SVC)
	@echo "$(GREEN)Frontend image built$(RESET)"

# =============================================================================
# Database
# =============================================================================

.PHONY: migrate
migrate: ## Apply all pending Alembic migrations
	$(COMPOSE) exec $(BACKEND_SVC) alembic upgrade head
	@echo "$(GREEN)Migrations applied$(RESET)"

.PHONY: migrations
migrations: ## Generate a new Alembic migration (MSG="description")
	@if [ -z "$(MSG)" ]; then \
		echo "Usage: make migrations MSG='your migration message'"; exit 1; \
	fi
	$(COMPOSE) exec $(BACKEND_SVC) alembic revision --autogenerate -m "$(MSG)"
	@echo "$(GREEN)Migration created$(RESET)"

.PHONY: migrate-down
migrate-down: ## Rollback last Alembic migration
	$(COMPOSE) exec $(BACKEND_SVC) alembic downgrade -1
	@echo "$(GREEN)Migration rolled back$(RESET)"

.PHONY: db-reset
db-reset: ## Drop and recreate the database (DESTRUCTIVE)
	@echo "WARNING: This will destroy all data. Press Ctrl+C to cancel..."
	@sleep 5
	$(COMPOSE) exec $(BACKEND_SVC) alembic downgrade base
	$(COMPOSE) exec $(BACKEND_SVC) alembic upgrade head
	@echo "$(GREEN)Database reset$(RESET)"

# =============================================================================
# Testing
# =============================================================================

.PHONY: test
test: test-backend ## Run all tests

.PHONY: test-backend
test-backend: ## Run backend tests with coverage
	$(COMPOSE) exec $(BACKEND_SVC) pytest tests/ \
		--cov=app \
		--cov-report=term-missing \
		--cov-report=html:htmlcov \
		--cov-report=xml:coverage.xml \
		-v
	@echo "$(GREEN)Backend tests complete — coverage in htmlcov/$(RESET)"

.PHONY: test-frontend
test-frontend: ## Run frontend tests
	@if [ -f frontend/package.json ]; then \
		cd frontend && npm test -- --watchAll=false; \
	else \
		echo "No frontend/package.json found, skipping"; \
	fi

.PHONY: test-local
test-local: ## Run backend tests locally (without Docker)
	cd backend && pytest tests/ \
		--cov=app \
		--cov-report=term-missing \
		-v

# =============================================================================
# Linting & Formatting
# =============================================================================

.PHONY: lint
lint: lint-backend lint-frontend ## Run all linters

.PHONY: lint-backend
lint-backend: ## Lint backend Python code with ruff
	$(COMPOSE) exec $(BACKEND_SVC) ruff check app/ tests/
	$(COMPOSE) exec $(BACKEND_SVC) mypy app/ --ignore-missing-imports
	@echo "$(GREEN)Backend lint passed$(RESET)"

.PHONY: lint-frontend
lint-frontend: ## Lint frontend with ESLint
	@if [ -f frontend/package.json ]; then \
		cd frontend && npm run lint; \
	else \
		echo "No frontend/package.json found, skipping"; \
	fi

.PHONY: format
format: ## Auto-format backend code with ruff
	$(COMPOSE) exec $(BACKEND_SVC) ruff format app/ tests/
	$(COMPOSE) exec $(BACKEND_SVC) ruff check --fix app/ tests/
	@echo "$(GREEN)Code formatted$(RESET)"

.PHONY: format-local
format-local: ## Auto-format code locally (without Docker)
	cd backend && ruff format app/ tests/ && ruff check --fix app/ tests/

# =============================================================================
# Shell Access
# =============================================================================

.PHONY: shell-backend
shell-backend: ## Open a bash shell in the backend container
	$(COMPOSE) exec $(BACKEND_SVC) /bin/bash

.PHONY: shell-db
shell-db: ## Open a psql shell in the postgres container
	$(COMPOSE) exec postgres psql \
		-U $${POSTGRES_USER:-sentinel} \
		-d $${POSTGRES_DB:-sentinel_db}

.PHONY: shell-redis
shell-redis: ## Open a redis-cli shell
	$(COMPOSE) exec redis redis-cli

# =============================================================================
# Utilities
# =============================================================================

.PHONY: env
env: ## Copy .env.example to .env if .env does not exist
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(GREEN).env created from .env.example — please update the secrets$(RESET)"; \
	else \
		echo ".env already exists, skipping"; \
	fi

.PHONY: secret
secret: ## Generate a secure random secret key
	@$(PYTHON) -c "import secrets; print(secrets.token_urlsafe(64))"

.PHONY: clean
clean: ## Remove build artefacts, caches, and stopped containers
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "coverage.xml" -delete 2>/dev/null || true
	find . -type f -name ".coverage" -delete 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	$(COMPOSE) rm -f 2>/dev/null || true
	@echo "$(GREEN)Clean complete$(RESET)"

.PHONY: clean-volumes
clean-volumes: down ## Remove all Docker volumes (DESTRUCTIVE)
	$(COMPOSE) down -v --remove-orphans
	@echo "$(GREEN)Volumes removed$(RESET)"
