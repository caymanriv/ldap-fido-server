# Makefile for client-side workflows

# Environment files (Vite modes)
development_env = .env.development
staging_env = .env.staging
testing_env = .env.testing
production_env = .env.production

.PHONY: help default install setup-dev-certs dev dev-with-certs build build-staging build-test build-prod preview clean check-licenses audit check-all

default: help

help:
	@echo "Available targets:"
	@echo "  install         Install dependencies"
	@echo "  setup-dev-certs Generate local development certificates"
	@echo "  dev             Start Vite dev server (mode: development)"
	@echo "  dev-with-certs   Generate certs then start Vite dev server"
	@echo "  build           Build client (default mode)"
	@echo "  build-staging    Build client (mode: staging)"
	@echo "  build-test       Build client (mode: test)"
	@echo "  build-prod       Build client (mode: production)"
	@echo "  preview         Preview the production build locally"
	@echo "  clean           Remove build output (dist/)"
	@echo "  check-licenses  Check licenses of production dependencies"
	@echo "  audit           Run security audit of dependencies"
	@echo "  check-all       Run all checks (licenses + audit)"

install:
	npm install

setup-dev-certs:
	npm run setup:dev-certs

dev:
	@echo "Starting client development server..."
	@if [ ! -f "$(development_env)" ]; then \
		echo "Warning: $(development_env) not found. Vite will fall back to defaults."; \
	fi
	npm run dev

dev-with-certs:
	@echo "Starting client development server (with local certs)..."
	@if [ ! -f "$(development_env)" ]; then \
		echo "Warning: $(development_env) not found. Vite will fall back to defaults."; \
	fi
	npm run dev:with-certs

build:
	npm run build

build-staging:
	@if [ ! -f "$(staging_env)" ]; then \
		echo "Warning: $(staging_env) not found. Vite will fall back to defaults."; \
	fi
	npm run build -- --mode staging

build-test:
	@if [ ! -f "$(testing_env)" ]; then \
		echo "Warning: $(testing_env) not found. Vite will fall back to defaults."; \
	fi
	npm run build -- --mode test

build-prod:
	@if [ ! -f "$(production_env)" ]; then \
		echo "Warning: $(production_env) not found. Vite will fall back to defaults."; \
	fi
	npm run build -- --mode production

preview:
	npm run preview

check-licenses:
	@echo "Checking licenses of production dependencies..."
	npx license-checker --production --onlyAllow 'MIT;ISC;BSD;Apache-2.0;0BSD'

audit:
	@echo "Running security audit of dependencies..."
	npm audit

check-all: check-licenses audit

clean:
	rm -rf dist
