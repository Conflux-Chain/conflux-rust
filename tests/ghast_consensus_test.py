#!/usr/bin/env python3
import subprocess
import os
import sys

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

TEST_INPUT = [
        "partial-invalid-case1.in",
        "partial-invalid-case2.in",
        "partial-invalid-case3.in",
        "partial-invalid-case4.in",
        "partial-invalid-case5.in",
        "crash-case1.in",
        "crash-case2.in",
        "era-case1.in",
        "era-case2.in",
        "recovery-case1.in",
        "recovery-case2.in",
        "adaptive-case1.in",
        "adaptive-case2.in",
        "adaptive-case3.in",
        "adaptive-case4.in"
        ]

test_dir = os.path.dirname(os.path.realpath(__file__))
cur_dir = os.getcwd()
os.chdir(cur_dir)
bench_cmd = os.getenv(
    "CONFLUX_BENCH",
    default=os.path.join(
        test_dir,
        "../target/release/consensus_bench"))
test_input_dir = os.path.join(test_dir, "./ghast_cases/")

failed = set()
for inp in TEST_INPUT:
    os.system("rm -rf " + test_dir + "/__consensus*")
    os.system("rm -rf " + test_dir + "/sqlite_db")
    print("Run Sub-testcase: " + inp)
    color = BLUE
    glyph = TICK
    try:
        subprocess.check_output(args = [bench_cmd, test_input_dir + inp, "--randomseed=1"], stdin = None, cwd = test_dir)
    except subprocess.CalledProcessError as err:
        color = RED
        glyph = CROSS
        print("Output of " + inp)
        print(err.output.decode("utf-8"))
        failed.add(inp)
    print(color[1] + glyph + " Sub-testcase " + inp + color[0])

os.system("rm -rf " + test_dir + "/__consensus*")

if len(failed) > 0:
    print("The following sub-test cases fail: ")
    for c in failed:
        print(c)
    sys.exit(1)
