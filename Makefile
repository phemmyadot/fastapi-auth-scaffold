.PHONY: dev migrate revision test lint seed

dev:
	uvicorn app.main:app --reload --port 8000

migrate:
	alembic upgrade head

revision:
	alembic revision --autogenerate -m "$(MSG)"

test:
	pytest -v

lint:
	ruff check . && mypy app/

seed:
	python -m app.scripts.seed_roles
