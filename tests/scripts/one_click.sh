#!/usr/bin/env bash
set -euxo pipefail

if [ $# -lt 2 ]; then
    echo "Parameters required: <key_pair> <instance_count> [<branch_name>]"
    exit 1
fi
key_pair="$1"
slave_count=$2
branch="${3:-master}"
slave_role=${key_pair}_exp_slave

run_latency_exp () {
    branch=$1
    exp_config=$2
    tps=$3

#     Create master instance and slave image
    ./create_slave_image.sh $key_pair $branch
    ./ip.sh --public

    # Launch slave instances
    master_ip=`cat ips`
    slave_image=`cat slave_image`
    ssh ubuntu@${master_ip} "cd ./conflux-rust/tests/scripts;rm -rf ~/.ssh/known_hosts;./launch-on-demand.sh $slave_count $key_pair $slave_role $slave_image;"

    # Run experiments
    ssh ubuntu@${master_ip} "cd ./conflux-rust/tests/scripts;python3 ./exp_latency.py --batch-config \"$exp_config\" --storage-memory-mb 16 --bandwidth 20 --tps $tps --enable-tx-propagation"

    # Terminate slave instances
    rm -rf tmp_data
    mkdir tmp_data
    cd tmp_data
    ../list-on-demand.sh $slave_role || true
    ../terminate-on-demand.sh
    cd ..

    # Download results
    archive_file="exp_stat_latency.tgz"
    log="exp_stat_latency.log"
    scp ubuntu@${master_ip}:~/conflux-rust/tests/scripts/${archive_file} .
    tar xfvz $archive_file
    cat $log
    mv $archive_file ${archive_file}.`date +%s`
    mv $log ${log}.`date +%s`

    # Terminate master instance and delete slave images
    # Comment this line if the data on the master instances are needed for further analysis
    ./terminate-on-demand.sh
}

# Parameter for one experiment is <block_gen_interval_ms>:<txs_per_block>:<tx_size>:<num_blocks>
# Different experiments in a batch is divided by commas
# Example: "250:1:150000:1000,250:1:150000:1000,250:1:150000:1000,250:1:150000:1000"
exp_config="250:1:500000:3000"

# For experiments with --enable-tx-propagation , <txs_per_block> * <tx_size> will be used as block size 
tps=4000
echo "start run $branch"
run_latency_exp $branch $exp_config $tps

# Comment this line if the data on the master instances are needed for further analysis
# ./terminate-on-demand.sh
