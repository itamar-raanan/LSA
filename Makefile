.PHONY: dev install test lint build up down

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"
	npm install

dev:
	docker compose -f deploy/docker-compose.yml up --build

test:
	.venv/bin/pytest
	npm test

lint:
	.venv/bin/ruff check apps scanner
	npm run lint

build:
	npm run build

up:
	docker compose -f deploy/docker-compose.yml up --build -d

down:
	docker compose -f deploy/docker-compose.yml down

