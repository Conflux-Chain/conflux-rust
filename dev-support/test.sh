#!/usr/bin/env bash

SCRIPT_DIR=`dirname "${BASH_SOURCE[0]}"`
echo "Checking dependent python3 modules ..."
source $SCRIPT_DIR/dep_pip3.sh
set -o pipefail

ROOT_DIR="$( cd $SCRIPT_DIR/.. && pwd )"
TEST_MAX_WORKERS="${1-8}"
TEST_MAX_RETRIES="${2-1}"
TEST_MAX_NODES="${3-24}"

export PYTHONUNBUFFERED=1
export CARGO_TARGET_DIR=$ROOT_DIR/build
export RUSTFLAGS="-g -D warnings"

CHECK_BUILD=1
CHECK_INT_TEST=2
CHECK_PY_TEST=3

function check_build {
    local -n inner_result=$1

    #rm -rf $ROOT_DIR/build && mkdir -p $ROOT_DIR/build
    pushd $ROOT_DIR > /dev/null

    local result

    result=$(
        cargo build --release| tee /dev/stderr
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

function check_integration_tests {
    local -n inner_result=$1

    pushd $ROOT_DIR > /dev/null
    local result
    result=$(
        # Make symbolic link for conflux binary to where integration test assumes its existence.
        rm -f target; ln -s build target
        ./tests/test_all.py --max-workers $TEST_MAX_WORKERS --max-retries $TEST_MAX_RETRIES --max-nodes $TEST_MAX_NODES | tee /dev/stderr
    )
    local exit_code=$?
    popd > /dev/null

    if [[ $exit_code -ne 0 ]]; then
        result="Integration test failed."$'\n'"$result"
    fi
    inner_result=($exit_code "$result")
}

function check_pytests {
    local -n inner_result=$1

    pushd $ROOT_DIR > /dev/null
    local result
    result=$(
        pytest ./integration_tests/tests -vv -n $TEST_MAX_WORKERS --dist loadscope | tee /dev/stderr
    )
    local exit_code=$?
    popd > /dev/null
    
    if [[ $exit_code -ne 0 ]]; then
        result="Pytest failed."$'\n'"$result"
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
# Integration test
declare -a test_result; check_integration_tests test_result; save_test_result test_result $CHECK_INT_TEST
# Pytest
declare -a test_result; check_pytests test_result; save_test_result test_result $CHECK_PY_TEST

