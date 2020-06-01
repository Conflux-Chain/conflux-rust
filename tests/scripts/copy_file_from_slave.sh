#!/bin/bash

set -e

if [[ $# -lt 1 ]]; then
    echo "Parameters required: <filename> [<tag>]"
    exit 1
fi

ip=`head -n 1 ips`

ssh ubuntu@$ip 'file=/tmp/`ls -t /tmp | grep conflux_test_ | head -n 1`/node0/'$1'; cp $file ~'
scp -o "StrictHostKeyChecking no" ubuntu@$ip:$1 ${2:-tag}.$1