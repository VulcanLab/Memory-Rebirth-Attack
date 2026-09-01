#!/usr/bin/env bash
# Run the three tool/agent experiments on the FULL 9-model set, each in its own graph
# partition, sequentially (the gateway rate-limits, so parallel heavy runs risk 429s).
# Model lists come from EXPLOIT_MODELS / PROPAGATION_MODELS / PERSISTENCE_MODELS in .env.
set -u
cd "$(dirname "$0")/.."
LOG=/tmp/full9.log
: > "$LOG"

echo "[$(date +%H:%M)] exploit (9 models) starting" | tee -a "$LOG"
MWE_GROUP_ID=mwe_exploit9 uv run python main.py exploit >>"$LOG" 2>&1
echo "[$(date +%H:%M)] exploit exit=$?" | tee -a "$LOG"

echo "[$(date +%H:%M)] propagation (9 models) starting" | tee -a "$LOG"
MWE_GROUP_ID=mwe_prop9 uv run python main.py propagation >>"$LOG" 2>&1
echo "[$(date +%H:%M)] propagation exit=$?" | tee -a "$LOG"

echo "[$(date +%H:%M)] persistence (9 models) starting" | tee -a "$LOG"
MWE_GROUP_ID=mwe_pers9 uv run python main.py persistence >>"$LOG" 2>&1
echo "[$(date +%H:%M)] persistence exit=$?" | tee -a "$LOG"

echo "[$(date +%H:%M)] ALL DONE" | tee -a "$LOG"
