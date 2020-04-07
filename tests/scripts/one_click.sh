#!/usr/bin/env bash
set -euxo pipefail

if [ $# -lt 2 ]; then
    echo "Parameters required: <key_pair> <instance_count> [<enable_flamegraph>] [<branch_name>] [<repository_url>]"
    exit 1
fi
key_pair="$1"
slave_count=$2
enable_flamegraph=${3:-false}
branch="${4:-master}"
repo="${5:-https://github.com/Conflux-Chain/conflux-rust}"
slave_role=${key_pair}_exp_slave

run_latency_exp () {
    branch=$1
    exp_config=$2
    tps=$3

    #1) Create master instance and slave image
    ./create_slave_image.sh $key_pair $branch $repo
    ./ip.sh --public

    #2) Launch slave instances
    master_ip=`cat ips`
    slave_image=`cat slave_image`
    ssh ubuntu@${master_ip} "cd ./conflux-rust/tests/scripts;rm -rf ~/.ssh/known_hosts;./launch-on-demand.sh $slave_count $key_pair $slave_role $slave_image;"

    #3) compile, and distributed binary to slaves: You can make change on the MASTER node and run the changed code against SLAVES nodes.
    ssh ubuntu@${master_ip} "cd ./conflux-rust/tests/scripts;cargo build --release --features \"deadlock_detection\";parallel-scp -O \"StrictHostKeyChecking no\" -h ips -l ubuntu -p 1000 ../../target/release/conflux ~ |grep FAILURE|wc -l;"

    #4) Run experiments
    flamegraph_option=""
    if [ $enable_flamegraph = true ]; then
        flamegraph_option="--enable-flamegraph"
    fi
    ssh ubuntu@${master_ip} "cd ./conflux-rust/tests/scripts;python3 ./exp_latency.py --vms $slave_count --batch-config \"$exp_config\" --storage-memory-gb 16 --bandwidth 20 --tps $tps --enable-tx-propagation --send-tx-period-ms 200 $flamegraph_option "

    #5) Terminate slave instances
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
exp_config="250:1:300000:2000"

# For experiments with --enable-tx-propagation , <txs_per_block> * <tx_size> will be used as block size 

tps=3000
echo "start run $branch"
run_latency_exp $branch $exp_config $tps

# Comment this line if the data on the master instances are needed for further analysis
# ./terminate-on-demand.sh
