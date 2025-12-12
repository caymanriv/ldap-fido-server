#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

find "$SCRIPT_DIR" -maxdepth 1 -type f -name "*.ldif" -exec chmod 0644 {} +
find "$SCRIPT_DIR" -maxdepth 1 -type f -name "*.sh" -exec chmod 0755 {} +

echo "Adjusted permissions in $SCRIPT_DIR:"
echo "- *.ldif -> 0644"
echo "- *.sh   -> 0755" 
