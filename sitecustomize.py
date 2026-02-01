import os
import multiprocessing

if os.environ.get("MUTANT_UNDER_TEST"):
    _original_set_start_method = multiprocessing.set_start_method

    def _safe_set_start_method(method, force=False):
        try:
            _original_set_start_method(method, force=force)
        except RuntimeError as exc:
            if "context has already been set" not in str(exc):
                raise

    multiprocessing.set_start_method = _safe_set_start_method
