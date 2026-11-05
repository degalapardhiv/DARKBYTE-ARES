# DARKBYTE ARES — developer shortcuts
SHELL := /bin/bash

.PHONY: help install lint test build check docker-up docker-down

help:
	@echo "DARKBYTE ARES"
	@echo "  make install    Create the Python venv and install backend/frontend dependencies"
	@echo "  make lint       Ruff + ESLint"
	@echo "  make test       pytest + Vitest"
	@echo "  make build      Production frontend build"
	@echo "  make check      lint + test + build"
	@echo "  make docker-up  Build and start the Docker Compose stack"
	@echo "  make docker-down Stop the stack (keeps volumes)"

install:
	python3.12 -m venv .venv
	.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
	cd frontend && npm ci

lint:
	.venv/bin/ruff check backend engines integrations scripts tests
	cd frontend && npm run lint

test:
	.venv/bin/python -m pytest -q
	cd frontend && npm run test

build:
	cd frontend && npm run build

check: lint test build

docker-up:
	docker compose up --build

docker-down:
	docker compose down
