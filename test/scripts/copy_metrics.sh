#!/bin/bash

set -e

ip=`head -n 1 ips`
ssh ubuntu@$ip "find /tmp/conflux_test_* -name metrics.log | grep node0 | xargs cat >> metrics.log"
scp -o "StrictHostKeyChecking no" ubuntu@$ip:metrics.log ${1:-tag}.metrics.log