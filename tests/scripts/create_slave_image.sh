#!/usr/bin/env bash
set -eu

export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2}
SCRIPT_DIR="$( cd "$(dirname "$0")" ; pwd -P )"

if [[ $# -lt 1 ]]; then
    echo "Parameters required: <keypair> [<branch>] [<repo>]"
    exit 1
fi

key_pair="$1"
branch="${2:-master}"
repo="${3:-https://github.com/Conflux-Chain/conflux-rust}"

echo "create an instance to make slave image ..."
$SCRIPT_DIR/launch-on-demand.sh 1 $key_pair ${key_pair}_master

echo "setup before making slave image ..."
master_ip=`cat ips`
master_id=`cat instances`
setup_script="setup_image.sh"
scp -o "StrictHostKeyChecking no" $SCRIPT_DIR/$setup_script ubuntu@$master_ip:~
# Add -tt to see a real-time line-buffered output.
ssh -tt ubuntu@$master_ip ./$setup_script $branch $repo

# create slave image
echo "create slave image ..."
res=`aws ec2 create-image --instance-id $master_id --name ${key_pair}_slave_image`
image_id=`echo $res | jq ".ImageId" | tr -d '"'`
echo "slave image created: $image_id"

# wait until image is available
while true
do
    image_info=`aws ec2 describe-images --image-ids $image_id`
    image_status=`echo $image_info | jq ".Images[].State" | tr -d '"'`
    echo "image is $image_status"
    if [ "$image_status" != "pending" ]; then
        break
    fi
    sleep 5
done

# The master instance will be used to run the scripts later, so we do not terminate it
# ./terminate-on-demand.sh

echo $image_id > slave_image
