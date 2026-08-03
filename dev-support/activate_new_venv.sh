#!/bin/bash

command -v uv >/dev/null 2>&1 || { echo "uv not found. Install: https://docs.astral.sh/uv/getting-started/installation/"; exit 1; }
uv venv --python 3.11 --allow-existing
source .venv/bin/activate
