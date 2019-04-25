#!/bin/bash

python3 stat_latency_map_reduce.py /tmp blocks.log

find /tmp/conflux_test_* -name conflux.log | xargs grep -i "thrott" > throttle.log
find /tmp/conflux_test_* -name conflux.log | xargs grep -i "error" > error.log
find /tmp/conflux_test_* -name conflux.log | xargs grep -i "txgen" > txgen.log
find /tmp/conflux_test_* -name conflux.log | xargs grep -i "packing" > tx_pack.log
find /tmp/conflux_test_* -name conflux.log | xargs grep -i "Partially invalid" > partially_invalid.log

tar cvfz log.tgz *.log

rm *.log
