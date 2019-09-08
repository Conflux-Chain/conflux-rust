#!/bin/bash

set -e

ip=`head -n 1 ips`

ssh ubuntu@$ip "find /tmp/conflux_test_* -name metrics.log | grep node0 | xargs cat >> metrics.log"
scp -o "StrictHostKeyChecking no" ubuntu@$ip:metrics.log ${1:-tag}.metrics.log

ssh ubuntu@$ip "find /tmp/conflux_test_* -name conflux.svg | grep node0 | xargs cat >> conflux.svg"
scp -o "StrictHostKeyChecking no" ubuntu@$ip:conflux.svg ${1:-tag}.conflux.svg