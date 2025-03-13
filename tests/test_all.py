#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor

PORT_MIN = 11000
PORT_MAX = 65535
PORT_RANGE = 100

# 64 to 113 is recommanded for user defined error code (https://tldp.org/LDP/abs/html/exitcodes.html). 
# 64 to 77 has been reserved in /usr/include/sysexits.h (https://stackoverflow.com/questions/1101957/are-there-any-standard-exit-status-codes-in-linux)
TEST_FAILURE_ERROR_CODE = 80

def run_single_test(py, script, test_dir, index, port_min, port_max):
    try:
        # Make sure python thinks it can write unicode to its stdout
        "\u2713".encode("utf_8").decode(sys.stdout.encoding)
        TICK = "✓ "
        CROSS = "✖ "
        CIRCLE = "○ "
    except UnicodeDecodeError:
        TICK = "P "
        CROSS = "x "
        CIRCLE = "o "

    BOLD, BLUE, RED, GREY = ("", ""), ("", ""), ("", ""), ("", "")
    if os.name == 'posix':
        # primitive formatting on supported
        # terminal via ANSI escape sequences:
        BOLD = ('\033[0m', '\033[1m')
        BLUE = ('\033[0m', '\033[0;34m')
        RED = ('\033[0m', '\033[0;31m')
        GREY = ('\033[0m', '\033[1;30m')
    print("Running " + script)
    port_min = port_min + (index * PORT_RANGE) % (port_max - port_min)
    color = BLUE
    glyph = TICK
    try:
        subprocess.check_output(args=[py, script, "--randomseed=1", f"--port-min={port_min}"],
                                stdin=None, cwd=test_dir)
    except subprocess.CalledProcessError as err:
        color = RED
        glyph = CROSS
        print(color[1] + glyph + " Testcase " + script + color[0])
        print("Output of " + script + "\n" + err.output.decode("utf-8"))
        raise err
    print(color[1] + glyph + " Testcase " + script + color[0])


def run():
    parser = argparse.ArgumentParser(usage="%(prog)s [options]")
    parser.add_argument(
        "--max-workers",
        dest="max_workers",
        default=8,
        type=int,
    )
    parser.add_argument(
        "--port-max",
        dest="port_max",
        default=PORT_MAX,
        type=int,
    )
    parser.add_argument(
        "--port-min",
        dest="port_min",
        default=PORT_MIN,
        type=int,
    )
    parser.add_argument(
        "--max-retries",
        dest="max_retries",
        default=1,
        type=int,
    )
    options = parser.parse_args()

    all_failed = set()

    # Retry the tests in multiple times to eliminate random fails
    for _ in range(options.max_retries):
        failed = run_single_round(options)

        failed_twice = [c for c in failed if c in all_failed]

        all_failed.update(failed)

        # If all test success, return the test
        if len(failed) == 0:
            return
        
        # If too many error happens, stop the test
        if len(failed) > 5:
            break
        
        # If some test failed in twice, stop the test
        if len(failed_twice) == 0:
            break


    print("The following test fails: ")
    for c in all_failed:
        print(c)
    sys.exit(TEST_FAILURE_ERROR_CODE)

def run_single_round(options):
    # Add slow tests to the front of the queue
    slow_tests = ["pos/retire_param_hard_fork_test.py"]
    TEST_SCRIPTS = slow_tests.copy()

    test_dir = os.path.dirname(os.path.realpath(__file__))

    test_subdirs = [
            "", # include test_dir itself
            "full_node_tests",
            "light",
            "network_tests",
            "pos",
            "pubsub",
            "evm_space",
            ]
    resource_heavy_tests = [
        "full_node_tests/p2p_era_test.py",
        "crash_test.py",
        "reorg_test.py",
        "crash_archive_era150_test.py",
        "pos/hard_fork_test.py",
        "erc20_test.py",
    ]

    # By default, run all *_test.py files in the specified subfolders.
    for subdir in test_subdirs:
        subdir_path = os.path.join(test_dir, subdir)
        for file in os.listdir(subdir_path):
            if file.endswith("_test.py"):
                rel_path = os.path.join(subdir, file)
                if rel_path not in resource_heavy_tests and rel_path not in slow_tests:
                    TEST_SCRIPTS.append(rel_path)

    executor = ProcessPoolExecutor(max_workers=options.max_workers)
    test_results = []
    pending_tasks = []

    py = "python3"
    if hasattr(sys, "getwindowsversion"):
        py = "python"

    i = 0
    slow_idx = 0
    test_idx = 0
    while slow_idx < len(resource_heavy_tests) or test_idx < len(TEST_SCRIPTS):
        # Check if there are any slow tests currently running
        has_pending_slow = any(
            (s in resource_heavy_tests) and not f.done()
            for s, f in test_results
        )

        # Prioritize submitting slow tests (when no slow test is running)
        if slow_idx < len(resource_heavy_tests) and not has_pending_slow:
            script = resource_heavy_tests[slow_idx]
            slow_idx += 1
        elif test_idx < len(TEST_SCRIPTS):
            script = TEST_SCRIPTS[test_idx]
            test_idx += 1
        else:
            break  # No more tasks to submit

        # Wait until number of pending tasks drops below threshold
        while len(pending_tasks) >= options.max_workers * 2:
            # Remove completed tasks
            pending_tasks = [task for task in pending_tasks if not task.done()]
            if len(pending_tasks) >= options.max_workers * 2:
                time.sleep(0.1)  # Brief sleep to avoid CPU spinning

        f = executor.submit(run_single_test, py, script, test_dir, i, options.port_min, options.port_max)
        pending_tasks.append(f)
        test_results.append((script, f))
        i += 1

    failed = set()
    for script, f in test_results:
        try:
            f.result()
        except subprocess.CalledProcessError as err:
            failed.add(script)
    return failed


if __name__ == '__main__':
    run()
