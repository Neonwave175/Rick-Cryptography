#!/bin/sh
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source $SCRIPT_DIR/.chatvenv/bin/activate
echo "Venv activated"
echo "Running !!"
python3 $SCRIPT_DIR/rickchat.py
