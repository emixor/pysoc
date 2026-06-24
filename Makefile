.PHONY: help install test test-unit test-integration demo lint clean tree

PYTHON ?= python
PIP ?= pip

help:  ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install:  ## Install PySOC in editable mode + dev dependencies
	$(PIP) install -e ".[dev]"

test:  ## Run the full test suite
	$(PYTHON) -m pytest -v

test-unit:  ## Run only unit tests
	$(PYTHON) -m pytest tests/unit -v

test-integration:  ## Run only integration tests
	$(PYTHON) -m pytest tests/integration -v

test-cov:  ## Run tests with coverage report
	$(PYTHON) -m pytest --cov=pysoc --cov-report=term-missing

demo:  ## Generate mock data, run the pipeline, and open the HTML dashboard
	$(PYTHON) -m pysoc generate --out data/raw
	$(PYTHON) -m pysoc run \
		data/raw/auth.log \
		data/raw/nginx_access.log \
		data/raw/apache_access.log \
		data/raw/windows_events.json \
		data/raw/impossible_travel.jsonl \
		--json-out data/output/report.json \
		--html-out data/output/report.html
	@echo
	@echo "✓ Done. Open the dashboard:"
	@echo "    xdg-open data/output/report.html   # Linux"
	@echo "    open data/output/report.html       # macOS"

lint:  ## Run ruff if available, otherwise no-op
	@command -v ruff >/dev/null 2>&1 && ruff check src tests || echo "ruff not installed, skipping"

clean:  ## Remove build artefacts and generated data
	rm -rf build dist *.egg-info src/*.egg-info
	rm -rf .pytest_cache .coverage htmlcov
	rm -rf data/raw/* data/output/*
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

tree:  ## Print the repository structure (requires `tree`)
	@command -v tree >/dev/null 2>&1 && tree -I '.venv|__pycache__|*.egg-info|build|dist|.pytest_cache' --dirsfirst || find . -type d -not -path '*/.git*' -not -path '*/__pycache__*' -not -path '*/.venv*' | sort
