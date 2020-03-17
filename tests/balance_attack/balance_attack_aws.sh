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

. $(dirname "$0")/../scripts/copy_logs_lib.sh

run_balance_attack () {
    pushd "$SCRIPTS_DIR"

    branch=$1

    #1) Create master instance and slave image
    ./create_slave_image.sh $key_pair $branch $repo
    ./ip.sh --public

    #2) Launch slave instances
    master_ip=`head -n1 ips`
    slave_image=`cat slave_image`
    ssh ubuntu@${master_ip} "cd ./conflux-rust/tests/scripts;
      rm -rf ~/.ssh/known_hosts;./launch-on-demand.sh $slave_count $key_pair $slave_role $slave_image;"

    #3) compile, and distributed binary to slaves: You can make change on the MASTER node and run the changed code against SLAVES nodes.
    ssh ubuntu@${master_ip} "cd ./conflux-rust/tests/scripts;
      cargo build --release --features \"deadlock_detection\";
      parallel-scp -O \"StrictHostKeyChecking no\" -h ips -l \
        ubuntu -p 1000 ../../target/release/conflux ~ |grep FAILURE|wc -l;"

    #4) Run experiments
    flamegraph_option=""
    if [ $enable_flamegraph = true ]; then
        flamegraph_option="--enable-flamegraph"
    fi
    ssh ubuntu@${master_ip} "cd ./conflux-rust/tests/scripts;
      python3 ../balance_attack/balance_attack_aws.py --generation-period-ms 250 --num-blocks 240 \
        --storage-memory-gb 16 --bandwidth 20 --tps 4000 --txs-per-block 1000 \
        --enable-tx-propagation --send-tx-period-ms 200 $flamegraph_option"

    #5) Terminate slave instances
    rm -rf tmp_data
    mkdir tmp_data
    pushd tmp_data
    ../list-on-demand.sh $slave_role || true
    ../terminate-on-demand.sh
    popd

    # Download results
    pushd ../balance_attack
    archive_file="conflux_logs.tgz"
    parallel-ssh -O "StrictHostKeyChecking no" -h ips -p 400 -t 600 "tar czvf \"$archive_file\" /tmp/conflux_test_*/*log /tmp/conflux_test_*/std*"
    copy_file_from_slaves "$archive_file" ips "logs.`date +%s`" "_$archive_file"
    wait_for_copy "$archive_file"
    popd

    # Terminate master instance and delete slave images
    # Comment this line if the data on the master instances are needed for further analysis
    ./terminate-on-demand.sh
}

echo "start run $branch"
THIS_DIR=$(dirname $(readlink -f "$0"))
SCRIPTS_DIR=$(readlink -f "$THIS_DIR/../scripts")
run_balance_attack $branch
