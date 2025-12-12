# Makefile for multi-environment Docker Compose workflows

# Environment paths
ENV_DIR = ../env
SERVER_ENV_DIR = $(ENV_DIR)/server
CLIENT_ENV_DIR = $(ENV_DIR)/client

# Compose files
development_compose = docker-compose.development.yml
test_compose = docker-compose.test.yml
staging_compose = docker-compose.staging.yml
production_compose = docker-compose.production.yml

# Environment files
development_env = $(SERVER_ENV_DIR)/development/.env
test_env = $(SERVER_ENV_DIR)/testing/.env
staging_env = $(SERVER_ENV_DIR)/staging/.env
production_env = $(SERVER_ENV_DIR)/production/.env

# License and audit targets
.PHONY: check-licenses audit check-all

check-licenses:
	@echo "Checking licenses of production dependencies..."
	npx license-checker --production --onlyAllow 'MIT;ISC;BSD;Apache-2.0;0BSD'

audit:
	@echo "Running security audit of dependencies..."
	npm audit

check-all: check-licenses audit

# Default target
.PHONY: help
default: help

help:
	@echo "Available targets:"
	@echo "  dev         Start development environment"
	@echo "  test        Run tests"
	@echo "  staging     Start staging environment"
	@echo "  prod        Start production environment"
	@echo "  down-*      Stop and remove containers for an environment"
	@echo "  down-all    Stop and remove all containers"
	@echo "  check-licenses  Check licenses of all dependencies"
	@echo "  audit          Run security audit of dependencies"
	@echo "  check-all    Run all checks (lint, test, licenses, audit)"

# Development environment
dev:
	@echo "Starting development environment..."
	@if [ ! -f "$(development_env)" ]; then \
		echo "Error: $(development_env) not found. Please create it from the example file."; \
		exit 1; \
	fi
	@echo "Fixing permissions on ./ldap directory..."
	@chmod -R ug+rw ./ldap 2>/dev/null || true
	@chown -R $$(id -u):$$(id -g) ./ldap 2>/dev/null || true
	docker compose --project-directory . -f $(development_compose) \
		--env-file $(development_env) \
		up --build

# Test environment
test:
	@echo "Starting test environment..."
	@if [ ! -f "$(test_env)" ]; then \
		echo "Error: $(test_env) not found. Please create it from the example file."; \
		exit 1; \
	fi
	docker compose --project-directory . -f $(test_compose) \
		--env-file $(test_env) \
		up --build --exit-code-from test

# Staging environment
staging:
	@echo "Starting staging environment..."
	@if [ ! -f "$(staging_env)" ]; then \
		echo "Error: $(staging_env) not found. Please create it from the example file."; \
		exit 1; \
	fi
	docker compose --project-directory . -f $(staging_compose) \
		--env-file $(staging_env) \
		up --build -d

# Production environment
prod:
	@echo "Starting production environment..."
	@if [ ! -f "$(production_env)" ]; then \
		echo "Error: $(production_env) not found. Please create it from the example file."; \
		exit 1; \
	fi
	docker compose --project-directory . -f $(production_compose) \
		--env-file $(production_env) \
		up --build -d

# Stop and remove containers
down-dev:
	docker compose -f $(development_compose) down -v

down-test:
	docker compose -f $(test_compose) down -v

down-staging:
	docker compose -f $(staging_compose) down -v

down-prod:
	docker compose -f $(production_compose) down -v

down-all: down-dev down-test down-staging down-prod

# Clean up
#clean: down-all
#	@echo "Cleaning up..."
#	docker system prune -f
#	docker volume prune -f

down-dev:
	docker compose --env-file $(development_env) -f $(development_compose) down -v

down-test:
	docker compose --env-file $(test_env) -f $(test_compose) down -v

down-staging:
	docker compose --env-file $(staging_env) -f $(staging_compose) down -v

down-prod:
	docker compose --env-file $(production_env) -f $(production_compose) down -v

down-all:
	docker compose --env-file $(development_env) -f $(development_compose) down -v
	docker compose --env-file $(test_env) -f $(test_compose) down -v
	docker compose --env-file $(staging_env) -f $(staging_compose) down -v
	docker compose --env-file $(production_env) -f $(production_compose) down -v

clean:
	docker system prune -af
