.PHONY: install test run-api run-ui run-cli lint docker-build docker-up

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v

run-api:
	uvicorn api:app --reload --port 8000

run-ui:
	cd frontend && npm run dev

run-cli:
	python agent.py

lint:
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics || true

docker-build:
	docker build -t cybersicker .

docker-up:
	docker compose up -d
