#!/bin/bash

ip_addr=`hostname --ip-address`
root_dir=$1
p2p_port_start=$2
num=$3

echo "root_dir = $1"
echo "p2p_port_start = $2"
echo "num_conflux = $3"

export RUST_BACKTRACE=full

for i in `seq 1 $num`
do
	nid=$(($i-1))
	wd=$root_dir/node$nid
	echo "start node $nid: $wd ..."
	cd $wd
	nohup cgexec -g net_cls:limit$i ~/conflux --config $root_dir/node$nid/conflux.conf --public-address $ip_addr:$(($p2p_port_start+$nid)) &
done
