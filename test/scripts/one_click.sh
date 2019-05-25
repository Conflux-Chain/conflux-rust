#!/usr/bin/env bash
set -euxo pipefail

if [ $# -lt 2 ]; then
    echo "Parameters required: <key_pair> <instance_count> [<branch_name>]"
    exit 1
fi
key_pair="$1"
slave_count=$2
branch="${3:-lpl_test}"
slave_role=${key_pair}_exp_slave

run_latency_exp () {
    branch=$1
    exp_name=$2
    exp_config=$3

    # Create master instance and slave image
    ./create_slave_image.sh $key_pair $branch

    # Launch slave instances
    master_ip=`cat ips`
    slave_image=`cat slave_image`
    ssh ubuntu@${master_ip} "cd ./conflux-rust/test/scripts;rm -rf ~/.ssh/known_hosts;./launch-on-demand.sh $slave_count $key_pair $slave_role $slave_image;"

    # Run experiments
    ssh ubuntu@${master_ip} "cd ./conflux-rust/test/scripts;python3 ./exp_latency.py --exp-name $exp_name --batch-config \"$exp_config\""

    # Terminate slave instances
    rm -rf tmp_data
    mkdir tmp_data
    cd tmp_data
    ../list-on-demand.sh $slave_role || true
    ../terminate-on-demand.sh
    cd ..

    # Download results
    archive_file="exp_stat_latency.tgz"
    archive_file_local="exp_stat_latency.tgz-$branch-$exp_name-$exp_config"
    log="exp_stat_latency.log"
    scp ubuntu@${master_ip}:~/conflux-rust/test/scripts/${archive_file} $archive_file_local
    tar xfvz $archive_file_local
    cat $log

    # Terminate master instance and delete slave images
    # Comment this line if the data on the master instances are needed for further analysis
    ./terminate-on-demand.sh
}

# Parameter for one experiment is <block_gen_interval_ms>:<txs_per_block>:<tx_size>:<num_blocks>:<tps>
# Different experiments in a batch is divided by commas
# Example: "250:1:150000:1000:4000,250:1:150000:1000:6000,250:1:150000:1000:8000,250:1:150000:1000:12000"
# Experiments for latency with the newest code, <txs_per_block> and <tx_size> will not take effects
latency_latest_default="250:1:150000:4000:"
exp_config=""
for tps in 6000 9000 12000
do
    exp_config="${exp_config}${latency_latest_default}${tps},"
done

branch="lpl_test"
echo "start run $branch"
run_latency_exp $branch "latency_latest" $exp_config

branch="lpl_test_old"
echo "start run $branch"
run_latency_exp $branch "latency_latest" $exp_config

# Comment this line if the data on the master instances are needed for further analysis
# ./terminate-on-demand.sh