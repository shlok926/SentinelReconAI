.PHONY: help install install-dev test lint format clean scan web-run db-init

help:
	@echo "SentinelRecon Development Commands"
	@echo "===================================="
	@echo "make install       - Install dependencies"
	@echo "make install-dev   - Install dev dependencies"
	@echo "make test          - Run tests"
	@echo "make lint          - Run linter (flake8)"
	@echo "make format        - Format code with black"
	@echo "make clean         - Remove build artifacts"
	@echo "make scan          - Run sample scan"
	@echo "make web-run       - Start Flask web UI"
	@echo "make db-init       - Initialize database"

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

test:
	pytest tests/ -v --cov=sentinelrecon

lint:
	flake8 sentinelrecon tests --max-line-length=100

format:
	black sentinelrecon tests

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf build/ dist/ *.egg-info/

scan:
	python -m sentinelrecon.cli.main scan --help

web-run:
	python -m sentinelrecon.web.app

db-init:
	python scripts/setup_db.py

.DEFAULT_GOAL := help
