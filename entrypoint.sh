#!/bin/sh
set -e
export FLASK_APP=${FLASK_APP:-app.py}

flask initdb || true
flask seed || true

exec "$@"
