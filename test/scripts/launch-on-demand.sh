#!/bin/bash

set -e

if [ $# -lt 3 ]; then
    echo "Parameters required: <instance_count> <keypair> <role>"
    exit 1
fi

if [[ -f instances ]]; then
    mv instances instances_old
fi

# launch AWS instances
region=us-west-2
n=$1
image="ami-0a37ce7034088596d" # experiment image
type="m5.xlarge"
keypair=$2
role=$3
res=`aws ec2 run-instances --region $region --image-id $image --count $n --key-name $keypair --instance-type $type --security-group-ids sg-0345bbb6934681ea1 --subnet-id subnet-a5cfe3dc --block-device-mapping DeviceName=/dev/xvda,Ebs={VolumeSize=100} --tag-specifications "ResourceType=instance,Tags=[{Key=role,Value=$role},{Key=Name,Value=$type-$image}]"`
echo $res | jq ".Instances[].InstanceId" | tr -d '"' > instances

num_created=`cat instances | wc -l`
if [ "$num_created" != "$1" ]; then
    echo "not enough instances created, required $n, created $num_created"
	exit 1
fi
echo "$1 instances created."

# wait for all instances in running state
while true
do
	instances=`aws ec2 describe-instances --filters Name=tag:role,Values=$role Name=instance-state-name,Values=running`
	num_runnings=`echo $instances | jq ".Reservations[].Instances[].InstanceId" | wc -l`
	echo "$num_runnings instances are running ..."
	if [[ $1 -le $num_runnings  ]]; then
		break
	fi
	sleep 3
done

# retrieve IPs and SSH all instances to update known_hosts
while true
do
    rm -f ~/.ssh/known_hosts
	./ip.sh
	if [[ $1 -eq `cat ~/.ssh/known_hosts | wc -l`  ]]; then
		break
	fi
done
wc -l ~/.ssh/known_hosts