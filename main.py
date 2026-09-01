#!/usr/bin/env python3
"""Memory Rebirth Attack, main entry point.

Dispatches to the experiment modules in attacks/, wiring up the shared harness in
core/. Run any experiment by name:

    uv run python main.py deterministic     # Exp 1: retrieval flaw (LLM-free)
    uv run python main.py e2e                # Exp 2: natural auto-invalidation
    uv run python main.py mcp                # Exp 3: MCP agent-tool surface
    uv run python main.py decision           # Exp 4: decision manipulation
    uv run python main.py scenarios          # Exp 5: guardrail bypass / unsafe ops
    uv run python main.py specificity        # Exp 6: specificity + scaling (LLM-free)
    uv run python main.py defense            # Exp 7: defense comparison + benign control
    uv run python main.py contamination      # Exp 8: poisoned decision written back
    uv run python main.py propagation        # Exp 9: spread across agents sharing a store
    uv run python main.py persistence        # Exp 10: decay with distance from the attack
    uv run python main.py exploit            # Exp 11: resurrected policy -> real tool action (sentinel tools)
    uv run python main.py seed               # LLM-free seeder (for MCP search-only)
    uv run python main.py reset              # wipe the group_id partition

Config is in .env (project root). Results are written to results/.
Directory layout:
    core/      shared harness (mwe_common.py wiring, mwe_patch.py runtime patches)
    attacks/   experiment + exploit scripts (attack_*.py, seed/reset helpers)
    results/   result_*.json / .txt outputs
    docs/      FINDINGS / GENERALIZATION / SETUP / RESEARCH_BRIEF / README
    config/    litellm_config.yaml
    tools/     shell/py runners (run_mcp_server.sh, run_experiments.py)
"""

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Make the harness (core/) and experiments (attacks/) importable by module name,
# so existing intra-package imports (e.g. `from mwe_common import ...`,
# `from attack_decision import ...`) keep working after the reorg.
for sub in ('core', 'attacks'):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

EXPERIMENTS = {
    'deterministic': 'attack_deterministic',
    'e2e': 'attack_e2e',
    'mcp': 'attack_mcp',
    'decision': 'attack_decision',
    'scenarios': 'attack_scenarios',
    'specificity': 'attack_specificity',
    'defense': 'attack_defense',
    'matrix': 'matrix',
    'contamination': 'attack_contamination',
    'propagation': 'attack_propagation',
    'persistence': 'attack_persistence',
    'exploit': 'attack_exploit_chain',
    'seed': 'seed_direct',
    'reset': 'reset_graph',
}


def usage():
    print('usage: python main.py <experiment>')
    print('experiments:', ', '.join(EXPERIMENTS))


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help', 'list'):
        usage(); return
    name = sys.argv[1]
    if name not in EXPERIMENTS:
        print(f'unknown experiment: {name}'); usage(); sys.exit(2)

    # Run from the project root. Experiments write through RESULTS_DIR (core/mwe_common),
    # which resolves relative paths against the project; an earlier version chdir'd into
    # a results directory, which made a relative RESULTS_DIR point somewhere else entirely.
    os.chdir(ROOT)

    mod = __import__(EXPERIMENTS[name])
    res = mod.main()
    if asyncio.iscoroutine(res):
        asyncio.run(res)


if __name__ == '__main__':
    main()
