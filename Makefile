.PHONY: install test lint typecheck format run-example clean

install:
	python3 -m pip install -e ".[dev]"

test:
	python3 -m pytest

lint:
	python3 -m ruff check .

typecheck:
	python3 -m mypy

format:
	python3 -m ruff format .

run-example:
	wizintel init
	wizintel tools check

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache build dist *.egg-info
