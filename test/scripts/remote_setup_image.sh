#!/bin/bash

set -e

if [ $# -lt 1 ]; then
    echo "Parameters required: <ip>"
    exit 1
fi

ip=$1

echo "copy scripts and binary ..."
scp -o "StrictHostKeyChecking no" throttle_bitcoin_bandwidth.sh $ip:~
scp -o "StrictHostKeyChecking no" remote_start_conflux.sh $ip:~
scp -o "StrictHostKeyChecking no" remote_collect_log.sh $ip:~
scp -o "StrictHostKeyChecking no" stat_latency_map_reduce.py $ip:~
scp -o "StrictHostKeyChecking no" ../../target/release/conflux $ip:~

echo "install tools ..."
ssh -o "StrictHostKeyChecking no" $ip "sudo apt install iotop -y"

sess_config=`ssh -o "StrictHostKeyChecking no" $ip 'grep "MaxSessions 50" /etc/ssh/sshd_config'`
if [ "$sess_config" = ""  ]; then
	set_max_sessions='echo "MaxSessions 50" | sudo tee -a /etc/ssh/sshd_config'
	set_max_startups='echo "MaxStartups 50:30:100" | sudo tee -a /etc/ssh/sshd_config'
	restart_sshd='sudo service sshd restart'
	
	echo "change the maximum sessions ..."
	ssh -o "StrictHostKeyChecking no" $ip "$set_max_sessions; $set_max_startups; $restart_sshd"
fi

