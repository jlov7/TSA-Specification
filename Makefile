.PHONY: verify verify-strict

PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

verify:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) tests/run_tests.py

verify-strict:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m compileall tools tests
	$(PYTHON) -m coverage run tests/run_tests.py -v
	$(PYTHON) -m coverage report --fail-under=100
	PYTHONPATH="$(PWD)" $(PYTHON) scripts/mutmut_run.py run
	$(PYTHON) -m mutmut results
