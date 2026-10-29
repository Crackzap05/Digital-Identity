#!/bin/bash
# Reliable wrapper for the Credential Desk backend.
# Keeps the server running even if it exits unexpectedly, and logs all output.
# Usage: bash backend/wrapper.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="/tmp/backend-wrapper.log"

echo "[$(date)] Starting backend wrapper" | tee -a "$LOG_FILE"

while true; do
    echo "[$(date)] Launching backend..." | tee -a "$LOG_FILE"
    cd "$PROJECT_ROOT"
    node backend/server.js >> "$LOG_FILE" 2>&1
    EXIT_CODE=$?
    echo "[$(date)] Backend exited with code $EXIT_CODE" | tee -a "$LOG_FILE"
    if [ $EXIT_CODE -eq 0 ]; then
        echo "[$(date)] Normal exit, not restarting" | tee -a "$LOG_FILE"
        break
    fi
    echo "[$(date)] Restarting in 2 seconds..." | tee -a "$LOG_FILE"
    sleep 2
done
