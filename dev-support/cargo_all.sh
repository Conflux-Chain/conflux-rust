#!/bin/bash

set -e

# Get the parent directory of the current directory as BASE_PATH
SCRIPT_DIR=$(dirname "$(realpath "$0")")
BASE_PATH=$(dirname "$SCRIPT_DIR")

# Check if the tools directory exists
if [ -d "$BASE_PATH/tools" ]; then
    # Iterate through each subdirectory under tools
    for dir in "$BASE_PATH"/tools/*; do
        if [ -d "$dir" ]; then
            echo "Running 'cargo $@' in $dir"
            # Change to the directory and run cargo command
            (cd "$dir" && cargo "$@")
        fi
    done
else
    echo "Error: $BASE_PATH/tools directory not found"
    exit 1
fi

# Run cargo command in the BASE_PATH directory
echo "Running 'cargo $@' in $BASE_PATH"
(cd "$BASE_PATH" && cargo "$@")