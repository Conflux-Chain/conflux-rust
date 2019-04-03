#!/bin/bash
bandwidth=$1
process_n=$2
DEV=eth0
if [[ ! -d '/sys/fs/cgroup/net_cls' ]]
then
	cli="	sudo apt install -y cgroup-bin;
		sudo modprobe cls_cgroup;
		sudo mkdir /sys/fs/cgroup/net_cls/;
		sudo mount -t cgroup net_cls -o net_cls /sys/fs/cgroup/net_cls/;
		sudo tc qdisc del dev $DEV;
		sudo tc qdisc add dev $DEV root handle 1: htb;
		sudo tc filter add dev $DEV parent 1: handle 1: cgroup;"
	echo $cli
	eval $cli
fi
if [[ ! -n $process_n ]]
then
	process_n=2
fi
echo $process_n
for i in `seq 1 $process_n`
do 
	if [[ ! -n `ls /sys/fs/cgroup/net_cls|grep limit$i` ]]
	then
		cli="	sudo cgcreate -g net_cls:limit$i -t lpl:lpl;"
		echo $cli
		eval $cli
	fi
  net_id=`printf "%02x" $i`
  echo 0x100$net_id | sudo tee /sys/fs/cgroup/net_cls/limit$i/net_cls.classid;
	
	if [[ -n `tc class show dev eth0|grep 1:$i` ]]
	then
		cli="sudo tc class change dev eth0 parent 1: classid 1:$net_id htb rate ${bandwidth}mbit ceil ${bandwidth}mbit"
		echo $cli
		eval $cli
	else
		cli="sudo tc class add dev eth0 parent 1: classid 1:$net_id htb rate ${bandwidth}mbit ceil ${bandwidth}mbit"
		echo $cli
		eval $cli
	fi
done
#pids=`ps -ef|grep kworker|awk '{print $2'}`
#cgexec -g net_cls:limit1 
