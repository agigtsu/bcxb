#!/usr/bin/env bash
set -euo pipefail

: "${CSV_PATH:?CSV_PATH environment variable is required}"
: "${TCPDUMP_FILTER:?TCPDUMP_FILTER environment variable is required}"
: "${CAPTURE_DURATION:?CAPTURE_DURATION environment variable is required}"
: "${CAPTURE_INTERVAL:?CAPTURE_INTERVAL environment variable is required}"

if [[ ! -f "$CSV_PATH" ]]; then
  echo "ERROR: CSV file not found: $CSV_PATH"
  exit 1
fi

while true; do
  echo "[$(date '+%Y-%m-%dT%H:%M:%S%z')] Starting tunnel packet capture for $CAPTURE_DURATION seconds"
  python3 /app/tunnel_tcpdump_to_csv.py \
    --csv "$CSV_PATH" \
    --filter "$TCPDUMP_FILTER" \
    --duration "$CAPTURE_DURATION"

  echo "[$(date '+%Y-%m-%dT%H:%M:%S%z')] Capture run complete, sleeping for $CAPTURE_INTERVAL seconds"
  sleep "$CAPTURE_INTERVAL"
done
