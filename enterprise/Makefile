.PHONY: check test coverage build

check:
	python -m ruff check src tests
	python -m mypy src/opspilot_enterprise

test:
	python -m pytest

coverage:
	python -m coverage run -m pytest
	python -m coverage report --show-missing --fail-under=75

build: check test
	python -m build
