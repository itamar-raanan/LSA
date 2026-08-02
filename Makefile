.PHONY: dev install test lint build docker-config docker-env up down logs ps

COMPOSE = docker compose --env-file deploy/.env -f deploy/docker-compose.yml

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"
	npm install

dev:
	$(MAKE) docker-env
	$(COMPOSE) up --build

test:
	.venv/bin/pytest
	npm test

lint:
	.venv/bin/ruff check apps scanner agent
	npm run lint

build:
	npm run build

docker-env:
	@test -f deploy/.env || { echo "Missing deploy/.env. Copy deploy/.env.example and replace every placeholder secret."; exit 1; }

docker-config: docker-env
	$(COMPOSE) config --quiet

up: docker-env
	$(COMPOSE) up --build -d --wait --wait-timeout 180

down: docker-env
	$(COMPOSE) down

logs: docker-env
	$(COMPOSE) logs -f --tail=200

ps: docker-env
	$(COMPOSE) ps
