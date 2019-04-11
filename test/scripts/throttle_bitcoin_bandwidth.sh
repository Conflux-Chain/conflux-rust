#!/bin/bash
bandwidth=$1
process_n=$2
DEV=ens5

if [ "`which cgcreate`" = "" ]; then
	echo "Install cgroup ..."
	sudo apt update
	sudo apt install -y cgroup-bin
	sudo modprobe cls_cgroup
fi

if [[ ! -d '/sys/fs/cgroup/net_cls' ]]
then
	echo "Mount cgroupo ..."
	sudo mkdir /sys/fs/cgroup/net_cls/
	sudo mount -t cgroup net_cls -o net_cls /sys/fs/cgroup/net_cls/
fi

sudo tc qdisc del dev $DEV
sudo tc qdisc add dev $DEV root handle 1: htb
sudo tc filter add dev $DEV parent 1: handle 1: cgroup

if [[ ! -n $process_n ]]
then
	process_n=2
fi
echo "Throttled nodes: $process_n"

for i in `seq 1 $process_n`
do 
	if [[ ! -n `ls /sys/fs/cgroup/net_cls|grep limit$i` ]]
	then
		cli="	sudo cgcreate -g net_cls:limit$i -t ubuntu:ubuntu;"
		echo $cli
		eval $cli
	fi

	net_id=`printf "%02x" $i`
	echo 0x100$net_id | sudo tee /sys/fs/cgroup/net_cls/limit$i/net_cls.classid;
	
	if [[ -n `tc class show dev $DEV|grep 1:$net_id` ]]
	then
		cli="sudo tc class change dev $DEV parent 1: classid 1:$net_id htb rate ${bandwidth}mbit ceil ${bandwidth}mbit"
		echo $cli
		eval $cli
	else
		cli="sudo tc class add dev $DEV parent 1: classid 1:$net_id htb rate ${bandwidth}mbit ceil ${bandwidth}mbit"
		echo $cli
		eval $cli
	fi
done
#pids=`ps -ef|grep kworker|awk '{print $2'}`
#cgexec -g net_cls:limit1 
