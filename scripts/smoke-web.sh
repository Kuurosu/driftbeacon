#!/usr/bin/env sh
set -eu

BASE_URL="${DRIFTBEACON_SMOKE_BASE_URL:-http://127.0.0.1:8080}"
TEST_REPOSITORY="${DRIFTBEACON_SMOKE_REPOSITORY:-https://github.com/Kuurosu/driftbeacon}"
ACCESS_CODE="${DRIFTBEACON_SMOKE_ACCESS_CODE:-}"
TIMEOUT_SECONDS="${DRIFTBEACON_SMOKE_TIMEOUT_SECONDS:-180}"
WORK_DIR="${DRIFTBEACON_SCAN_WORK_DIR:-}"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

echo "Checking liveness..."
curl -fsS "$BASE_URL/health/live" >"$tmp_dir/live.json"

echo "Checking readiness..."
curl -fsS "$BASE_URL/health/ready" >"$tmp_dir/ready.json"

echo "Submitting $TEST_REPOSITORY..."
headers="$tmp_dir/headers.txt"
if [ -n "$ACCESS_CODE" ]; then
  curl -fsS -D "$headers" -o /dev/null \
    -X POST \
    --data-urlencode "repository_url=$TEST_REPOSITORY" \
    --data-urlencode "beta_access_code=$ACCESS_CODE" \
    "$BASE_URL/scans"
else
  curl -fsS -D "$headers" -o /dev/null \
    -X POST \
    --data-urlencode "repository_url=$TEST_REPOSITORY" \
    "$BASE_URL/scans"
fi

location="$(awk 'tolower($1) == "location:" {gsub("\r", "", $2); print $2}' "$headers" | tail -1)"
if [ -z "$location" ]; then
  echo "No Location header returned by scan submission." >&2
  exit 1
fi
scan_id="${location##*/}"
echo "Queued scan $scan_id."

deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
status="queued"
while [ "$(date +%s)" -lt "$deadline" ]; do
  curl -fsS "$BASE_URL/api/scans/$scan_id" >"$tmp_dir/status.json"
  status="$(python - "$tmp_dir/status.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("status", "unknown"))
PY
)"
  echo "Status: $status"
  case "$status" in
    completed) break ;;
    failed|expired)
      cat "$tmp_dir/status.json" >&2
      exit 1
      ;;
  esac
  sleep 2
done

if [ "$status" != "completed" ]; then
  echo "Timed out waiting for scan completion." >&2
  exit 1
fi

echo "Fetching report page..."
curl -fsS "$BASE_URL/scans/$scan_id" >"$tmp_dir/report.html"

echo "Fetching Markdown..."
curl -fsS "$BASE_URL/scans/$scan_id/report.md" >"$tmp_dir/report.md"

echo "Fetching JSON..."
curl -fsS "$BASE_URL/scans/$scan_id/report.json" >"$tmp_dir/report.json"
python -m json.tool "$tmp_dir/report.json" >/dev/null

if grep -E "/Users/|/private/tmp|/work/scans|/data/web.sqlite3" \
  "$tmp_dir/report.html" "$tmp_dir/report.md" "$tmp_dir/report.json" >/dev/null; then
  echo "Smoke test found an internal path in public report output." >&2
  exit 1
fi

if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
  if find "$WORK_DIR" -maxdepth 3 -type d -name repository | grep . >/dev/null; then
    echo "Smoke test found a retained repository clone under $WORK_DIR." >&2
    exit 1
  fi
fi

echo "Smoke test passed for $BASE_URL/scans/$scan_id"
