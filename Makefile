.PHONY: install test lint typecheck format run-sample web worker clean

PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3.12)
PYTHONPATH ?= src

install:
	./scripts/install-local.sh

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .

typecheck:
	$(PYTHON) -m mypy src

format:
	$(PYTHON) -m ruff format .

run-sample:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m driftbeacon run \
		--repository-path . \
		--output-dir .driftbeacon-sample \
		--previous-scan examples/previous-scan.json \
		--checkov-json examples/sample-checkov.json \
		--trivy-json examples/sample-trivy.json \
		--no-slack

web:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m driftbeacon web --port 8080 --local-dev

worker:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m driftbeacon worker

clean:
	rm -rf .driftbeacon .driftbeacon-sample .pytest_cache .mypy_cache .ruff_cache *.egg-info build dist
