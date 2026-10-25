#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PYTHONPATH=".:backend"

# Load the same local configuration used by Pydantic Settings. An explicit
# database URL must win over readiness-based fallback selection.
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if [[ -n "${MOBILE_PENTEST_DATABASE_URL:-}" ]]; then
  echo "Using the explicitly configured database URL."
elif command -v pg_isready >/dev/null 2>&1 && pg_isready -q; then
  echo "Using PostgreSQL at the configured host."
else
  echo "PostgreSQL is unavailable; using the local SQLite demo database."
  export MOBILE_PENTEST_DATABASE_URL="sqlite:///./storage/masa.sqlite3"
fi

PYTHON_BIN="./myenv/bin/python"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="python"
fi

exec "$PYTHON_BIN" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
