#!/bin/bash

SCRIPT_DIR=`dirname "${BASH_SOURCE[0]}"`
echo "Checking dependent python3 modules ..."
source $SCRIPT_DIR/dep_pip3.sh
set -o pipefail

ROOT_DIR="$( cd $SCRIPT_DIR/.. && pwd )"

export PYTHONUNBUFFERED=1
export CARGO_TARGET_DIR=$ROOT_DIR/build
export RUSTFLAGS="-g -D warnings"

function check_build {
    local -n test_reuslt=$1

    #rm -rf $ROOT_DIR/build && mkdir -p $ROOT_DIR/build
    pushd $ROOT_DIR > /dev/null

    local result
    result=`cargo build --release && cargo test --release --all --no-run && cargo bench --all --no-run`
    local exit_code=$?

    popd > /dev/null

    if [[ $exit_code -ne 0 ]]; then
        result="Build failed."$'\n'"$result"
    else
        result="Build succeeded."
    fi
    test_result=($exit_code "$result")
}

function check_unit_tests {
    local -n test_reuslt=$1

    pushd $ROOT_DIR > /dev/null
    local result
    result=`cargo test --release --all`
    local exit_code=$?
    popd > /dev/null

    if [[ $exit_code -ne 0 ]]; then
        result="Unit tests failed."$'\n'"$result"
    fi
    test_result=($exit_code "$result")
}

function check_integration_tests {
    local -n test_reuslt=$1

    pushd $ROOT_DIR > /dev/null
    local result
    result=$(
        # Make symbolic link for conflux binary to where integration test assumes its existence.
        rm -f target; ln -s build target
        ./test/test_all.py | tee /dev/stderr
    )
    local exit_code=$?
    popd > /dev/null

    if [[ $exit_code -ne 0 ]]; then
        result="Integration test failed."$'\n'"$result"
    fi
    test_result=($exit_code "$result")
}

function save_test_result {
    local -n test_reuslt=$1
    local exit_code=${test_result[0]}
    local result=${test_result[1]}

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
# Unit tests
declare -a test_result; check_unit_tests test_result; save_test_result test_result
# Integration test
declare -a test_result; check_integration_tests test_result; save_test_result test_result

