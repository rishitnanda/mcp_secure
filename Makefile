.PHONY: install test run-shield run-box build-sandbox-image clean bench_data

# Point this to your actual folder name (e.g., venv instead of .venv)
VENV = venv
PYTHON = $(shell [ -f $(VENV)/bin/python ] && echo $(VENV)/bin/python || echo python3)
PIP = $(shell [ -f $(VENV)/bin/pip ] && echo $(VENV)/bin/pip || echo pip3)
PYTEST = $(shell [ -f $(VENV)/bin/pytest ] && echo $(VENV)/bin/pytest || echo pytest)
BENCH_OUT = benchmark/bench_results.log

install:
	$(PIP) install -r mcp_shield/requirements.txt
	$(PIP) install -r mcp_box/requirements.txt

test:
	$(PYTEST) tests/ -v

run-shield:
	$(VENV)/bin/uvicorn mcp_shield.src.gateway:app --reload --host 127.0.0.1 --port 8000

run-box:
	@echo "MCP-Box is designed to run in-process as a module imported by MCP-Shield."
	@echo "To test the sandbox system run: make test"

build-sandbox-image:
	docker build -t mcp-box-sandbox:latest ./mcp_box/

bench_data:
	@rm -f $(BENCH_OUT)
	@mkdir -p benchmark
	-$(PYTEST) benchmark/cross_server_ablation.py -s -v >> $(BENCH_OUT) 2>&1
	-$(PYTEST) benchmark/false_positives_single_turn.py -s -v >> $(BENCH_OUT) 2>&1
	-$(PYTEST) benchmark/false_positives_multi_turn.py -s -v >> $(BENCH_OUT) 2>&1
	-$(PYTEST) benchmark/mcp_shield_latency_overhead.py -s -v >> $(BENCH_OUT) 2>&1
	-$(PYTEST) benchmark/multi_turn_telemetry.py -s -v >> $(BENCH_OUT) 2>&1
	-$(PYTEST) benchmark/multi_turn_window_size.py -s -v >> $(BENCH_OUT) 2>&1

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	rm -rf .pytest_cache
	rm -f $(BENCH_OUT)