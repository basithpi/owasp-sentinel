.PHONY: up down logs build rebuild migrate shell test lint clean seed fmt check help

COMPOSE         := docker compose
BACKEND_SERVICE := backend
COMPOSE_FILE    := docker-compose.yml

# Colours
BOLD   := \033[1m
RESET  := \033[0m
GREEN  := \033[32m
YELLOW := \033[33m
CYAN   := \033[36m

help: ## Show this help message
	@echo "$(BOLD)OWASP Sentinel v3 — Phantom Strike$(RESET)"
	@echo ""
	@echo "$(CYAN)Usage:$(RESET)  make $(BOLD)<target>$(RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-18s$(RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ── Docker lifecycle ──────────────────────────────────────────────────────────
up: ## Start all services in detached mode
	@echo "$(YELLOW)Starting Sentinel services...$(RESET)"
	@cp -n .env.example .env 2>/dev/null || true
	$(COMPOSE) -f $(COMPOSE_FILE) up -d
	@echo "$(GREEN)✓ Services started. Run 'make logs' to tail output.$(RESET)"

down: ## Stop all services
	@echo "$(YELLOW)Stopping Sentinel services...$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) down
	@echo "$(GREEN)✓ Services stopped.$(RESET)"

restart: ## Restart all services
	$(COMPOSE) -f $(COMPOSE_FILE) restart

logs: ## Tail logs for all services (Ctrl-C to exit)
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f

logs-%: ## Tail logs for a specific service (e.g. make logs-backend)
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f $*

build: ## Build all Docker images
	@echo "$(YELLOW)Building images...$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) build --parallel
	@echo "$(GREEN)✓ Build complete.$(RESET)"

rebuild: ## Force-rebuild all images (no cache)
	@echo "$(YELLOW)Rebuilding images without cache...$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) build --no-cache --parallel
	@echo "$(GREEN)✓ Rebuild complete.$(RESET)"

pull: ## Pull latest images from registry
	$(COMPOSE) -f $(COMPOSE_FILE) pull

ps: ## Show running containers and their status
	$(COMPOSE) -f $(COMPOSE_FILE) ps

# ── Database ──────────────────────────────────────────────────────────────────
migrate: ## Run Alembic database migrations (upgrade head)
	@echo "$(YELLOW)Running database migrations...$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) alembic upgrade head
	@echo "$(GREEN)✓ Migrations applied.$(RESET)"

migrate-down: ## Rollback the last Alembic migration
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) alembic downgrade -1

migrate-status: ## Show current migration status
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) alembic current

migrate-history: ## Show full migration history
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) alembic history --verbose

makemigration: ## Generate a new migration (MSG="description")
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) alembic revision --autogenerate -m "$(MSG)"

seed: ## Seed the database with initial data
	@echo "$(YELLOW)Seeding database...$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) python -m app.scripts.seed
	@echo "$(GREEN)✓ Database seeded.$(RESET)"

# ── Developer shells ──────────────────────────────────────────────────────────
shell: ## Open a bash shell in the backend container
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) /bin/bash

shell-db: ## Open a psql shell in the postgres container
	$(COMPOSE) -f $(COMPOSE_FILE) exec postgres psql -U $${POSTGRES_USER:-sentinel} -d $${POSTGRES_DB:-sentinel}

shell-redis: ## Open a redis-cli shell
	$(COMPOSE) -f $(COMPOSE_FILE) exec redis redis-cli -a $${REDIS_PASSWORD:-changeme}

shell-frontend: ## Open a bash shell in the frontend container
	$(COMPOSE) -f $(COMPOSE_FILE) exec frontend /bin/sh

# ── Testing ───────────────────────────────────────────────────────────────────
test: ## Run the full backend test suite with pytest
	@echo "$(YELLOW)Running backend tests...$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) pytest tests/ -v --tb=short --cov=app --cov-report=term-missing
	@echo "$(GREEN)✓ Tests complete.$(RESET)"

test-fast: ## Run tests excluding slow/integration tests
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) pytest tests/ -v -m "not slow and not integration"

test-integration: ## Run integration tests only
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) pytest tests/ -v -m "integration"

test-coverage: ## Run tests and export HTML coverage report to htmlcov/
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) \
		pytest tests/ --cov=app --cov-report=html --cov-report=xml
	@echo "$(GREEN)✓ Coverage report written to backend/htmlcov/index.html$(RESET)"

test-frontend: ## Run frontend tests with vitest
	$(COMPOSE) -f $(COMPOSE_FILE) exec frontend npm run test

# ── Linting & formatting ──────────────────────────────────────────────────────
lint: ## Run ruff linter on backend source
	@echo "$(YELLOW)Linting backend...$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) ruff check app tests
	@echo "$(GREEN)✓ Lint passed.$(RESET)"

lint-frontend: ## Run ESLint on frontend source
	$(COMPOSE) -f $(COMPOSE_FILE) exec frontend npm run lint

fmt: ## Auto-format backend code with ruff + black
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) ruff check --fix app tests
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) black app tests

typecheck: ## Run mypy static type checking on backend
	$(COMPOSE) -f $(COMPOSE_FILE) exec $(BACKEND_SERVICE) mypy app --ignore-missing-imports

typecheck-frontend: ## Run tsc type checking on frontend
	$(COMPOSE) -f $(COMPOSE_FILE) exec frontend npm run typecheck

check: lint typecheck ## Run all lint + type checks

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean: ## Stop containers and remove volumes (DESTRUCTIVE)
	@echo "$(YELLOW)WARNING: This will delete all container data including the database.$(RESET)"
	@read -p "Are you sure? [y/N] " ans && [ "$$ans" = "y" ]
	$(COMPOSE) -f $(COMPOSE_FILE) down -v --remove-orphans
	@echo "$(GREEN)✓ Cleaned up containers and volumes.$(RESET)"

clean-images: ## Remove all Sentinel Docker images
	$(COMPOSE) -f $(COMPOSE_FILE) down --rmi local

prune: ## Docker system prune (removes all unused objects)
	docker system prune -af --volumes

# ── Utility ───────────────────────────────────────────────────────────────────
env: ## Copy .env.example to .env if .env does not exist
	@test -f .env && echo ".env already exists, skipping." || (cp .env.example .env && echo "$(GREEN)✓ .env created from .env.example. Please update the values.$(RESET)")

health: ## Check health of all running services
	@echo "$(CYAN)Checking service health...$(RESET)"
	@$(COMPOSE) -f $(COMPOSE_FILE) ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

minio-init: ## Create default MinIO bucket
	$(COMPOSE) -f $(COMPOSE_FILE) exec minio mc alias set local http://localhost:9000 $${MINIO_ROOT_USER:-minioadmin} $${MINIO_ROOT_PASSWORD:-changeme123}
	$(COMPOSE) -f $(COMPOSE_FILE) exec minio mc mb local/$${MINIO_BUCKET:-sentinel-reports} --ignore-existing
