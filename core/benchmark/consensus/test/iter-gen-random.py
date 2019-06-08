#!/usr/bin/env python3
import os
import sys

script_dir = os.path.dirname(os.path.realpath(__file__))
cur_dir = os.getcwd()
os.chdir(script_dir)
while True:
    os.system("rm -rf __*")
    os.system("./gen-random-graph " + " ".join(sys.argv[1:]))
    ret = os.system("../target/release/consensus_bench rand.in")
    ret = ret >> 8
    if ret != 0:
        os.system("rm -rf __*")
        break
