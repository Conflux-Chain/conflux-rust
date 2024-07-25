#!/usr/bin/env bash

SCRIPT_DIR=`dirname "${BASH_SOURCE[0]}"`
echo "Checking dependent python3 modules ..."
source $SCRIPT_DIR/dep_pip3.sh
set -o pipefail

ROOT_DIR="$( cd $SCRIPT_DIR/.. && pwd )"
TEST_MAX_WORKERS="${1-6}"
TEST_MAX_RETRIES="${2-1}"

export PYTHONUNBUFFERED=1
export CARGO_TARGET_DIR=$ROOT_DIR/build
export RUSTFLAGS="-g -D warnings"

CHECK_BUILD=1
CHECK_CLIPPY=2
CHECK_UNIT_TEST=3
CHECK_INT_TEST=4

function check_build {
    local -n inner_result=$1

    #rm -rf $ROOT_DIR/build && mkdir -p $ROOT_DIR/build
    pushd $ROOT_DIR > /dev/null

    local result

    result=$(
        cargo build --release && cargo doc --document-private-items && cargo test --release --all --no-run && cargo bench --all --no-run && ./dev-support/check-crates.sh | tee /dev/stderr
    )

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
    result=$(
        ./cargo_fmt.sh --install && ./cargo_fmt.sh -- --check && cargo clippy --release --all -- -A warnings | tee /dev/stderr
    )
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
    result=$(
       cargo test --release --all | tee /dev/stderr
    )
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
        ./tests/test_all.py --max-workers $TEST_MAX_WORKERS --max-retries $TEST_MAX_RETRIES | tee /dev/stderr
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
    local stage_number=$2
    local exit_code=${inner_result[0]}
    local result=${inner_result[1]}
    
    if [[ $exit_code -ne 0 ]]; then
        printf "%s\n" "$result" >> $ROOT_DIR/.phabricator-comment
        if [[ $exit_code -eq 80 ]] && [[ $stage_number -eq $CHECK_INT_TEST ]]; then
            ## If the test fails for "test case error in the integration test", return customized exit code
            exit 80
        fi
        exit 1
    fi
}

echo -n "" > $ROOT_DIR/.phabricator-comment
mkdir -p $ROOT_DIR/build

# Build
declare -a test_result; check_build test_result; save_test_result test_result $CHECK_BUILD
# fmt and clippy tests
declare -a test_result; check_fmt_and_clippy test_result; save_test_result test_result $CHECK_CLIPPY
# Unit tests
declare -a test_result; check_unit_tests test_result; save_test_result test_result $CHECK_UNIT_TEST
# Integration test
declare -a test_result; check_integration_tests test_result; save_test_result test_result $CHECK_INT_TEST

