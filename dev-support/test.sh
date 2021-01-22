#!/usr/bin/env bash

SCRIPT_DIR=`dirname "${BASH_SOURCE[0]}"`
echo "Checking dependent python3 modules ..."
source $SCRIPT_DIR/dep_pip3.sh
set -o pipefail

ROOT_DIR="$( cd $SCRIPT_DIR/.. && pwd )"
TEST_MAX_WORKERS="${1-8}"

export PYTHONUNBUFFERED=1
export CARGO_TARGET_DIR=$ROOT_DIR/build
export RUSTFLAGS="-g -D warnings"

function check_build {
    local -n inner_result=$1

    #rm -rf $ROOT_DIR/build && mkdir -p $ROOT_DIR/build
    pushd $ROOT_DIR > /dev/null

    local result

    result=`cargo build --release && cargo test --release --all --no-run && cargo bench --all --no-run \
    && ( cd core/benchmark/storage && RUSTFLAGS="" cargo build --release )`

    local exit_code=$?

    popd > /dev/null

    if [[ $exit_code -ne 0 ]]; then
        result="Build failed."$'\n'"$result"
    else
        result="Build succeeded."
    fi
    inner_result=($exit_code "$result")
}

function check_fmt_and_clippy {
    local -n inner_result=$1

    pushd $ROOT_DIR > /dev/null
    local result
    SAVED_RUSTFLAGS=$RUSTFLAGS
    SAVED_CARGO_DIR=$CARGO_TARGET_DIR
    export RUSTFLAGS="-g"
    export CARGO_TARGET_DIR="$ROOT_DIR/build_clippy"
    result=`./cargo_fmt.sh -- --check && cargo clippy --release --all -- -A warnings`
    export RUSTFLAGS=$SAVED_RUSTFLAGS
    export CARGO_TARGET_DIR=$SAVED_CARGO_DIR
    local exit_code=$?
    popd > /dev/null

    if [[ $exit_code -ne 0 ]]; then
        result="fmt and clippy tests failed."$'\n'"$result"
    fi
    inner_result=($exit_code "$result")
}

function check_unit_tests {
    local -n inner_result=$1

    pushd $ROOT_DIR > /dev/null
    local result
    result=`cargo test --release --all`
    local exit_code=$?
    popd > /dev/null

    if [[ $exit_code -ne 0 ]]; then
        result="Unit tests failed."$'\n'"$result"
    fi
    inner_result=($exit_code "$result")
}

function check_integration_tests {
    local -n inner_result=$1

    pushd $ROOT_DIR > /dev/null
    local result
    result=$(
        # Make symbolic link for conflux binary to where integration test assumes its existence.
        rm -f target; ln -s build target
        ./tests/test_all.py --max-workers $TEST_MAX_WORKERS| tee /dev/stderr
    )
    local exit_code=$?
    popd > /dev/null

    if [[ $exit_code -ne 0 ]]; then
        result="Integration test failed."$'\n'"$result"
    fi
    inner_result=($exit_code "$result")
}

function save_test_result {
    local -n inner_result=$1
    local exit_code=${inner_result[0]}
    local result=${inner_result[1]}

    printf "%s\n" "$result"
    
    if [[ $exit_code -ne 0 ]]; then
        printf "%s\n" "$result" >> $ROOT_DIR/.phabricator-comment
        exit 1
    fi
}

echo -n "" > $ROOT_DIR/.phabricator-comment
mkdir -p $ROOT_DIR/build

# Build
declare -a test_result; check_build test_result; save_test_result test_result
# fmt and clippy tests
declare -a test_result; check_fmt_and_clippy test_result; save_test_result test_result
# Unit tests
declare -a test_result; check_unit_tests test_result; save_test_result test_result
# Integration test
declare -a test_result; check_integration_tests test_result; save_test_result test_result

