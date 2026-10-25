#!/usr/bin/env bash
set -u

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ok=0

# Use the same local configuration as the Python application when checking
# configured tool paths. .env is a trusted project-local configuration file;
# values are exported for the checks but never printed as raw assignments.
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

check_file() {
  local label="$1"
  local path="$2"
  if [[ -f "$path" || -x "$path" ]]; then
    printf 'OK   %-12s %s\n' "$label" "$path"
  else
    printf 'MISS %-12s %s\n' "$label" "$path"
    ok=1
  fi
}

check_command() {
  local label="$1"
  local command="$2"
  if command -v "$command" >/dev/null 2>&1; then
    printf 'OK   %-12s %s\n' "$label" "$(command -v "$command")"
  else
    printf 'MISS %-12s command: %s\n' "$label" "$command"
    ok=1
  fi
}

check_command java java
check_file apktool "${MOBILE_PENTEST_APKTOOL_JAR_PATH:-$HOME/.local/share/masa/apktool.jar}"
check_file jadx "${MOBILE_PENTEST_JADX_JAR_PATH:-$HOME/.local/share/masa/jadx-cli-all.jar}"
check_command adb adb

if command -v pg_isready >/dev/null 2>&1 && pg_isready -q; then
  printf '%s\n' 'OK   postgres     accepting connections'
else
  printf '%s\n' 'INFO postgres     unavailable; SQLite fallback is supported'
fi

if (( ok != 0 )); then
  printf '%s\n' 'Environment needs attention before the complete demo.'
  exit 1
fi

printf '%s\n' 'Environment is ready for static MASA analysis.'
