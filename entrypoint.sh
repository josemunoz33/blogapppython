#!/bin/sh
set -e
export FLASK_APP=app.py
flask initdb || true
exec "$@"
