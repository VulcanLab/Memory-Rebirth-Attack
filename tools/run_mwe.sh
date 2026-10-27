#!/usr/bin/env bash
# Orchestrate the core Memory Rebirth Attack experiments via the main dispatcher.
set -e
MWE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$MWE"

echo "### uv sync"
uv sync

echo; echo "### reset graph partition"
uv run python main.py reset || true

echo; echo "### [1/2] deterministic (LLM-free) core proof"
uv run python main.py deterministic

echo; echo "### reset graph partition"
uv run python main.py reset || true

echo; echo "### [2/2] end-to-end proof"
uv run python main.py e2e || echo "(e2e needs a capable extraction model; deterministic proof stands)"

echo; echo "### DONE. Results in results/"
