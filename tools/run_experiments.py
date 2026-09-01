"""Cross-platform runner (Windows / macOS / Linux), dispatches via main.py.

Runs: reset -> deterministic (Exp1) -> reset -> e2e (Exp2).
Usage:
    uv run python tools/run_experiments.py            # both
    uv run python tools/run_experiments.py det         # Exp1 only
    uv run python tools/run_experiments.py e2e         # Exp2 only
"""

import subprocess
import sys
from pathlib import Path

MAIN = Path(__file__).resolve().parent.parent / 'main.py'


def run(exp: str) -> int:
    print(f'\n=== main.py {exp} ===', flush=True)
    return subprocess.call([sys.executable, str(MAIN), exp])


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else 'all'
    run('reset')
    if which in ('all', 'det'):
        run('deterministic')
    if which in ('all', 'e2e'):
        run('reset')
        run('e2e')
    print('\nDONE. Results in results/')


if __name__ == '__main__':
    main()
