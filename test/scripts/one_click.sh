#!/usr/bin/env bash
set -euxo pipefail
key_pair="$1"
branch="${2:-lpl_test}"
slave_role=${key_pair}_exp_slave

./create_slave_image.sh $key_pair $branch

slave_count=5
master_ip=`cat ips`
slave_image=`cat slave_image`

ssh ubuntu@${master_ip} "cd ./conflux-rust/test/scripts;./launch-on-demand.sh $slave_count $key_pair $slave_role $slave_image; python3 ./exp_latency.py --exp-name latency_latest"

rm -rf tmp_data
mkdir tmp_data
cd tmp_data
../list-on-demand.sh $slave_role
../terminate-on-demand.sh
