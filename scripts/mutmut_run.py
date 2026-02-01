import os
import shutil
import sys
from pathlib import Path

import mutmut.__main__ as mutmut_main


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "run":
        mutants_dir = Path("mutants")
        if mutants_dir.exists():
            shutil.rmtree(mutants_dir)
    stats_path = Path("mutants") / "mutmut-stats.json"
    if stats_path.exists():
        stats_path.unlink()
    if os.environ.get("MUTMUT_DISABLE_TIMEOUT_THREAD", "1") == "1":

        class _NoOpThread:
            def __init__(self, *args, **kwargs):
                pass

            def start(self):
                return None

        mutmut_main.Thread = _NoOpThread
    if os.environ.get("MUTMUT_DISABLE_SETPROCTITLE", "1") == "1":
        mutmut_main.setproctitle = lambda *args, **kwargs: None
    if len(sys.argv) >= 2 and sys.argv[1] == "run" and "--max-children" not in sys.argv:
        max_children = os.environ.get("MUTMUT_MAX_CHILDREN", "1")
        sys.argv[2:2] = ["--max-children", str(max_children)]
    sys.modules["mutmut.__main__"] = mutmut_main
    mutmut_main.cli()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
