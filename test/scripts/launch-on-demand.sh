#!/bin/bash
set -e
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2}
SCRIPT_DIR="$( cd "$(dirname "$0")" ; pwd -P )"

if [ $# -lt 3 ]; then
    echo "Parameters required: <instance_count> <keypair> <role> [<image_id>]"
    exit 1
elif [ $# -eq 4 ]; then
    image="$4"
    type="m5.xlarge"
    public=""
elif [[ -f slave_image ]]; then
    image=`cat slave_image`
    type="m5.xlarge"
    public=""
else
    # create master instances
    image="ami-087ea399212e0aab4" # experiment image
    type="m5.2xlarge"
    public="--public"
fi

if [[ -f instances ]]; then
    mv instances instances_old
fi

# launch AWS instances
n=$1
keypair=$2
role=$3
res=`aws ec2 run-instances --image-id $image --count $n --key-name $keypair --instance-type $type --security-group-ids sg-0345bbb6934681ea1 --subnet-id subnet-a5cfe3dc --block-device-mapping DeviceName=/dev/xvda,Ebs={VolumeSize=100} --tag-specifications "ResourceType=instance,Tags=[{Key=role,Value=$role},{Key=Name,Value=$type-$image}]"`
echo $res | jq ".Instances[].InstanceId" | tr -d '"' > instances

num_created=`cat instances | wc -l`
if [ "$num_created" -ne "$1" ]; then
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

echo "Back up ~/.ssh/known_hosts to ./known_hosts_backup"
echo "Wait for launched instances able to be connected"
mv ~/.ssh/known_hosts known_hosts_backup
# retrieve IPs and SSH all instances to update known_hosts
while true
do
    rm -f ~/.ssh/known_hosts
    $SCRIPT_DIR/ip.sh $public
    if [[ $1 -eq `cat ~/.ssh/known_hosts | wc -l`  ]]; then
        break
    fi
done
wc -l ~/.ssh/known_hosts
echo "Restore known_hosts"
mv known_hosts_backup ~/.ssh/known_hosts
