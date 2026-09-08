PYTHON ?= python3
VENV := .venv
BIN := $(VENV)/bin
PIP := $(BIN)/pip
PY := $(BIN)/python

.PHONY: install seed test demo seal clean

install: $(VENV)/pyvenv.cfg
	$(PIP) install -e ".[dev,postgres,mysql]"

$(VENV)/pyvenv.cfg:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install -U pip

seed: install
	$(PY) scripts/gen_seed.py

test: seed
	$(BIN)/pytest -q

demo: seed
	$(PY) scripts/demo.py
	$(PY) scripts/demo_walkthrough.py

# Exactly 4 core cases; exit non-zero on mismatch. See SEAL.md.
seal: seed
	$(PY) scripts/seal.py

clean:
	rm -rf $(VENV) src/write_gate.egg-info .pytest_cache
	rm -f seed/warehouse.duckdb seed/warehouse.duckdb.wal seed/orders.csv
	rm -f .logs/*.jsonl
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true