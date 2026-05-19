.PHONY: install test run-shield run-box build-sandbox-image clean

VENV = .venv
PYTHON = $(shell [ -f $(VENV)/bin/python3 ] && echo $(VENV)/bin/python3 || echo python3)
PIP = $(shell [ -f $(VENV)/bin/pip3 ] && echo $(VENV)/bin/pip3 || echo pip3)
PYTEST = $(shell [ -f $(VENV)/bin/pytest ] && echo $(VENV)/bin/pytest || echo pytest)

install:
	$(PIP) install -r mcp_shield/requirements.txt
	$(PIP) install -r mcp_box/requirements.txt

test:
	$(PYTEST) tests/ -v

run-shield:
	uvicorn mcp_shield.src.gateway:app --reload --host 127.0.0.1 --port 8000

run-box:
	@echo "MCP-Box is designed to run in-process as a module imported by MCP-Shield."
	@echo "To test the sandbox system run: make test"

build-sandbox-image:
	docker build -t mcp-box-sandbox:latest ./mcp_box/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	rm -rf .pytest_cache
