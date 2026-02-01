from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_run_tests_module():
    path = Path(__file__).with_name("run_tests.py")
    spec = importlib.util.spec_from_file_location("run_tests_module", path)
    if spec is None or spec.loader is None:
        raise AssertionError("Failed to load run_tests.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_full_run_tests():
    module = _load_run_tests_module()
    _passed, failed = module.run_all(verbose=False)
    assert failed == 0
