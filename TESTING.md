# Testing

## Setup

Use a virtual environment (recommended, and avoids PEP 668 system restrictions):

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install -r requirements-dev.txt
```

## Run the test suite (fast)

```bash
make verify
```

## Stricter checks (slow)

```bash
make verify-strict
```

## Notes

- The test harness is `tests/run_tests.py`.
- `make verify` runs lint + format checks and the full test harness.
- `make verify-strict` adds bytecode compilation, coverage gating (100% on `tools/`), and mutation testing.
- Mutation testing defaults to `MUTMUT_MAX_CHILDREN=1` for stability; override with
  `MUTMUT_MAX_CHILDREN=<n>` to speed up on multi-core machines.
