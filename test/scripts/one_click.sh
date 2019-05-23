#!/usr/bin/env bash
set -euxo pipefail
key_pair="$1"
if false; then
branch="${2:-master}"
./create_slave_image.sh $key_pair $branch
fi
slave_count=5
master_ip=`cat ips`
slave_image=`cat slave_image`
ssh ubuntu@${master_ip} "cd ./conflux-rust/test/scripts;./launch-on-demand.sh $slave_count $key_pair ${key_pair}_exp_slave $slave_image; python3 ./exp_latency.py"