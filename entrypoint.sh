#!/bin/sh
set -eu

is_enabled() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

export FLASK_APP="${FLASK_APP:-app.py}"

if is_enabled "${AUTO_INIT_DB:-true}"; then
  flask initdb
fi

if is_enabled "${AUTO_SEED_DB:-true}"; then
  flask seed
fi

exec "$@"
