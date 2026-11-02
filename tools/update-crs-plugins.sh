#!/bin/sh
# Download only the immutable commits recorded in the reviewed manifest.
set -eu
exec python3 "$(dirname "$0")/update-crs-plugins.py" "$@"
