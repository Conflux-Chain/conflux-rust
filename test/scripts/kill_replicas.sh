#!/bin/bash

shopt -s  expand_aliases
which pssh || alias pssh='parallel-ssh'
pssh -O "StrictHostKeyChecking no" -h ips -p 400 "killall -9 conflux || echo already killed"