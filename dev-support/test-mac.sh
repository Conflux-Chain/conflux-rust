#!/bin/bash

ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )"/.. && pwd )"

function check_build {
    local test_reuslt=$1

    export CARGO_TARGET_DIR=$ROOT_DIR/build
    export RUSTFLAGS="-D warnings"

    #rm -rf $ROOT_DIR/build && mkdir -p $ROOT_DIR/build
    pushd $ROOT_DIR > /dev/null

    local result
    result=`cargo build -v --release && (cd core/benchmark/storage && cargo build -v --release)`
    local exit_code=$?

    popd $ROOT_DIR > /dev/null

    unset CARGO_TARGET_DIR
    unset RUSTFLAGS

    if [[ $exit_code -ne 0 ]]; then
        result="Build failed."$'\n'"$result"
    else
        result="Build succeeded."
    fi
    echo "$result"
}

function check_client_tests {
    local test_reuslt=$1

    pushd $ROOT_DIR/client > /dev/null
    local result
    result=`CARGO_TARGET_DIR=$ROOT_DIR/build RUSTFLAGS="-D warnings" cargo test`
    local exit_code=$?
    popd > /dev/null

    if [[ $exit_code -ne 0 ]]; then
        result="Unit test in client failed."$'\n'"$result"
    fi
    echo "$result"
}

function check_core_tests {
    local test_reuslt=$1

    pushd $ROOT_DIR/core > /dev/null
    local result
    result=`CARGO_TARGET_DIR=$ROOT_DIR/build RUSTFLAGS="-D warnings" cargo test`
    local exit_code=$?
    popd > /dev/null

    if [[ $exit_code -ne 0 ]]; then
        result="Unit test in core failed."$'\n'"$result"
    fi
    echo "$result"
}

function check_integration_tests {
    local test_reuslt=$1

    pushd $ROOT_DIR > /dev/null
    local result
    result=$(
        # Make symbolic link for conflux binary to where integration test assumes its existence.
        rm -rf target; ln -s build target
        ./tests/test_all.py
        pytest ./integration_tests/tests -vv -n 6 --dist loadscope
    )
    local exit_code=$?
    popd > /dev/null

    if [[ $exit_code -ne 0 ]]; then
        result="Integration test failed."$'\n'"$result"
    fi
    echo "$result"
}

echo -n "" > $ROOT_DIR/.phabricator-comment
mkdir -p $ROOT_DIR/build

declare -a test_result; check_build test_result
declare -a test_result; check_core_tests test_result
declare -a test_result; check_client_tests test_result
declare -a test_result; check_integration_tests test_result

