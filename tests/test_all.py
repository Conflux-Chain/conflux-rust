#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
from test_utils.test_scheduler import TestScheduler
from test_framework.test_framework import TEST_EXIT_INTERRUPT

PORT_MIN = 11000
PORT_MAX = 65535
PORT_RANGE = 100

# 64 to 113 is recommanded for user defined error code (https://tldp.org/LDP/abs/html/exitcodes.html). 
# 64 to 77 has been reserved in /usr/include/sysexits.h (https://stackoverflow.com/questions/1101957/are-there-any-standard-exit-status-codes-in-linux)
TEST_FAILURE_ERROR_CODE = 80

def run_single_test(py, script, test_dir, index, port_min, port_max, conflux_binary):
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
        YELLOW = ('\033[0m', '\033[0;33m') 
    print("Running " + script)
    port_min = port_min + (index * PORT_RANGE) % (port_max - port_min)
    color = BLUE
    glyph = TICK
    try:
        subprocess.check_output(args=[py, script, "--randomseed=1", f"--port-min={port_min}", f"--conflux-binary={conflux_binary}", "--cleanup-on-interrupt"],
                                stdin=None, cwd=test_dir)
    except subprocess.CalledProcessError as err:
        if err.returncode == TEST_EXIT_INTERRUPT:
            color = YELLOW
            print(color[1] + CIRCLE + " Testcase interrupted " + script + color[0])
            return

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
        "--max-nodes",
        dest="max_nodes",
        default=24,
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
    parser.add_argument(
        "--conflux-binary",
        dest="conflux",
        default=os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "../target/release/conflux"),
        type=str)
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
    TEST_SCRIPTS = []

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
    slow_tests = {"full_node_tests/p2p_era_test.py", "pos/retire_param_hard_fork_test.py"}

    # By default, run all *_test.py files in the specified subfolders.
    for subdir in test_subdirs:
        subdir_path = os.path.join(test_dir, subdir)
        for file in os.listdir(subdir_path):
            if file.endswith("_test.py"):
                rel_path = os.path.join(subdir, file)
                if rel_path not in slow_tests:
                    TEST_SCRIPTS.append(rel_path)

    py = "python3"
    if hasattr(sys, "getwindowsversion"):
        py = "python"
        
    scheduler = TestScheduler(
        task_executable=run_single_test,
        py=py,
        test_dir=test_dir,
        max_workers=options.max_workers,
        available_nodes=options.max_nodes,
        port_min=options.port_min,
        port_max=options.port_max,
        conflux_binary=options.conflux,
    )
    
    failed_tests = scheduler.schedule(list(slow_tests) + TEST_SCRIPTS)
    return failed_tests


if __name__ == '__main__':
    run()
