#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
from concurrent.futures import ProcessPoolExecutor

PORT_MIN = 11000
PORT_MAX = 65535
PORT_RANGE = 100


def run_single_test(py, script, test_dir, index):
    print("Running " + script)
    port_min = PORT_MIN + (index * PORT_RANGE) % (PORT_MAX - PORT_MIN)
    return subprocess.check_output(args=[py, script, "--randomseed=1", f"--port-min={port_min}"],
                                   stdin=None, cwd=test_dir)


def run():
    parser = argparse.ArgumentParser(usage="%(prog)s [options]")
    parser.add_argument(
        "--max-workers",
        dest="max_workers",
        default=8,
        type=int,
    )
    options = parser.parse_args()

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

    TEST_SCRIPTS = []

    test_dir = os.path.dirname(os.path.realpath(__file__))

    test_subdirs = [
            "", # include test_dir itself
            "full_node_tests",
            "light",
            "network_tests",
            "pubsub",
            ]

    # By default, run all *_test.py files in the specified subfolders.
    for subdir in test_subdirs:
        subdir_path = os.path.join(test_dir, subdir)
        for file in os.listdir(subdir_path):
            if file.endswith("_test.py"):
                rel_path = os.path.join(subdir, file)
                TEST_SCRIPTS.append(rel_path)

    executor = ProcessPoolExecutor(max_workers=options.max_workers)
    test_results = []
    for i in range(len(TEST_SCRIPTS)):
        script = TEST_SCRIPTS[i]
        py = "python3"

        if hasattr(sys, "getwindowsversion"):
            py = "python"

        f = executor.submit(run_single_test, py, script, test_dir, i)
        test_results.append((script, f))

    failed = set()
    for script, f in test_results:
        color = BLUE
        glyph = TICK
        try:
            f.result()
        except subprocess.CalledProcessError as err:
            color = RED
            glyph = CROSS
            print("Output of " + script)
            print(err.output.decode("utf-8"))
            failed.add(script)
        print(color[1] + glyph + " Testcase " + script + color[0])

    if len(failed) > 0:
        print("The following test fails: ")
        for c in failed:
            print(c)
        sys.exit(1)


if __name__ == '__main__':
    run()
