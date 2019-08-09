#!/bin/bash

python3 stat_latency_map_reduce.py /tmp blocks.log

find /tmp/conflux_test_* -name conflux.log | xargs grep -i "thrott\|Start Generating Workload" > throttle.log
find /tmp/conflux_test_* -name conflux.log | xargs grep -i "error\|Start Generating Workload" > error.log
find /tmp/conflux_test_* -name conflux.log | xargs grep -i "txgen\|Start Generating Workload" > txgen.log
find /tmp/conflux_test_* -name conflux.log | xargs grep -i "packing\|Start Generating Workload" > tx_pack.log
find /tmp/conflux_test_* -name conflux.log | xargs grep -i "Partially invalid\|Start Generating Workload" > partially_invalid.log
find /tmp/conflux_test_* -name conflux.log | xargs grep -i "Sampled transaction\|Start Generating Workload" > tx_sample.log

tar cvfz log.tgz *.log

rm *.log
