#!/bin/sh
# Read /run/secrets/* into env vars before exec'ing python -m <module>.
# File name convention: secret-name -> SECRET_NAME (lower→upper, hyphen→underscore)
# This is the pre-AWS source. AWS replaces ./secrets/ with Parameter Store fetch.
set -e
if [ -d /run/secrets ]; then
    for f in /run/secrets/*; do
        [ -f "$f" ] || continue
        name=$(basename "$f" | tr '[:lower:]-' '[:upper:]_')
        val=$(cat "$f")
        export "$name=$val"
    done
fi
exec python -m "$@"
