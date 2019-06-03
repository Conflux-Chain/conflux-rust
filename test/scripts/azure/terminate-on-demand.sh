#!/bin/bash

set -e

if [ $# -lt 1 ]; then
    echo "Parameters required: <resource_group>"
    exit 1
fi

az group delete -n $1 -y --no-wait

rm -rf ips*