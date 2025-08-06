#!/bin/bash

INPUT_FILE="labitbu.json"
OUTPUT_FILE="labitbu_index.json"
PATHOLOGY_SERVER_URL="http://0.0.0.0"

if [ ! -f "$INPUT_FILE" ]; then
  echo "Error: Input file '$INPUT_FILE' not found."
  exit 1
fi

echo "Processing TXIDs from $INPUT_FILE..."

process_txid() {
  local index=$1
  local txid=$2
  local inscription_id="${txid}i0"
  local url="${PATHOLOGY_SERVER_URL}/inscription/${inscription_id}"

  local html_response
  html_response=$(curl -s -f "$url")

  if [ $? -ne 0 ]; then
    echo "Warning: Failed to fetch data for TXID $txid (URL: $url)" >&2
    return
  fi

  local sat
  sat=$(echo "$html_response" | grep -A 1 '<dt>sat</dt>' | tail -n 1 | sed 's/<[^>]*>//g' | tr -d '[:space:]')

  if [[ -n "$sat" ]]; then
    jq -n --argjson index "$index" --arg txid "$txid" --arg sat "$sat" '{"index": $index, "txid": $txid, "sat": $sat}'
    echo "Found sat for $txid" >&2
  else
    echo "Warning: Could not find sat for TXID $txid" >&2
  fi
}

export -f process_txid
export PATHOLOGY_SERVER_URL

jq -r 'to_entries[] | "\(.key + 1) \(.value.txid)"' "$INPUT_FILE" \
  | xargs -n 2 -P 4 bash -c 'process_txid "$@"' _ \
  | jq -s 'sort_by(.index)' > "$OUTPUT_FILE"

echo "Done. Results saved to $OUTPUT_FILE"