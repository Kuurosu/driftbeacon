#!/usr/bin/env sh
set -eu

PYTHON_BIN="${PYTHON:-python3.12}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  printf '%s\n' "Python 3.12 is required. Install it or run with PYTHON=/path/to/python3.12." >&2
  exit 1
fi

create_venv() {
  "$PYTHON_BIN" -m venv .venv
}

verify_venv() {
  if [ ! -x .venv/bin/python ]; then
    printf '%s\n' "Existing .venv is incomplete." >&2
    return 1
  fi

  .venv/bin/python - <<'PY'
import sys

if sys.version_info[:2] != (3, 12):
    raise SystemExit("Existing .venv is not Python 3.12.")
PY
}

repair_venv() {
  backup=".venv.broken.$(date +%Y%m%d%H%M%S)"
  printf '%s\n' "Moving broken .venv to $backup and creating a fresh Python 3.12 venv."
  mv .venv "$backup"
  create_venv
}

if [ ! -d .venv ]; then
  create_venv
fi

if ! verify_venv; then
  repair_venv
  verify_venv
fi

. .venv/bin/activate
python -m pip install --upgrade pip

if python -m pip show driftbeacon >/dev/null 2>&1; then
  if ! python -m pip uninstall -y driftbeacon; then
    deactivate 2>/dev/null || true
    repair_venv
    . .venv/bin/activate
    python -m pip install --upgrade pip
  fi
fi

python -m pip install -e ".[dev]"

cat > .venv/bin/DriftBeacon <<'EOF'
#!/usr/bin/env sh
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
PYTHONPATH="$REPO_DIR/src${PYTHONPATH:+:$PYTHONPATH}" exec "$SCRIPT_DIR/python" -m DriftBeacon "$@"
EOF
chmod +x .venv/bin/DriftBeacon

if [ ! -x .venv/bin/DriftBeacon ]; then
  printf '%s\n' "Install completed but .venv/bin/DriftBeacon was not created." >&2
  printf '%s\n' "Try removing the local virtualenv and reinstalling: rm -rf .venv && ./scripts/install-local.sh" >&2
  exit 1
fi

printf '%s\n' "DriftBeacon installed. Run: . .venv/bin/activate && DriftBeacon --help"
