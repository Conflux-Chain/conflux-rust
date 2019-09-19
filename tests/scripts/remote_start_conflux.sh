#!/bin/bash

ip_addr=`hostname --ip-address`
root_dir=$1
p2p_port_start=$2
num=$3
bandwidth="${4:-20}"
flamegraph_enabled="${5:-false}"

echo "root_dir = $1"
echo "p2p_port_start = $2"
echo "num_conflux = $3"

export RUST_BACKTRACE=full

# support perf
if [ $flamegraph_enabled = true ]; then
	sudo apt install -y linux-tools-common
	sudo apt install -y linux-tools-`uname -r`
	echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
fi

# limit bandwidth
./throttle_bitcoin_bandwidth.sh $bandwidth $num

for i in `seq 1 $num`
do
	nid=$(($i-1))
	wd=$root_dir/node$nid
	echo "start node $nid: $wd ..."
	cd $wd
	
	if [ $flamegraph_enabled = true ]; then
		nohup cgexec -g net_cls:limit$i flamegraph -o $root_dir/node$nid/conflux.svg ~/conflux --config $root_dir/node$nid/conflux.conf --public-address $ip_addr:$(($p2p_port_start+$nid)) &
	else
		nohup cgexec -g net_cls:limit$i ~/conflux --config $root_dir/node$nid/conflux.conf --public-address $ip_addr:$(($p2p_port_start+$nid)) &
	fi
done
