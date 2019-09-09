#!/bin/bash

set -e

ip=`head -n 1 ips`

ssh ubuntu@$ip 'file=`find /tmp/conflux_test_* -name metrics.log | grep node0`; cp $file ~'
scp -o "StrictHostKeyChecking no" ubuntu@$ip:metrics.log ${1:-tag}.metrics.log

ssh ubuntu@$ip 'file=`find /tmp/conflux_test_* -name conflux.svg | grep node0`; cp $file ~'
scp -o "StrictHostKeyChecking no" ubuntu@$ip:conflux.svg ${1:-tag}.conflux.svg