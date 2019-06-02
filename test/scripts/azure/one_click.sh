#!/bin/bash

set -e

if [ $# -lt 3 ]; then
    echo "Parameters required: <resource_group> <instance_count> <exp_config> [<branch>]"
    exit 1
fi

group=$1
num_slaves=$2
exp_config=$3
branch="${4:-master}"

./create_slave_image.sh $group $branch

./launch-on-demand.sh $group $num_slaves

master_ip=`cat ips_master`
scp -o "StrictHostKeyChecking no" ips ubuntu@$master_ip:~/conflux-rust/test/scripts
echo "begin to run experiment on master VM ..."
ssh ubuntu@$master_ip "cd ./conflux-rust/test/scripts; python3 ./exp_latency.py --batch-config $exp_config --tps 100 --enable-tx-propagation"

scp ubuntu@$master_ip:~/conflux-rust/test/scripts/exp_stat_latency.tgz .
scp ubuntu@$master_ip:~/conflux-rust/test/scripts/exp_stat_latency.log .

tar xfvz $archive_file exp_stat_latency.tgz

echo "cleanup ..."
./terminate-on-demand.sh $group