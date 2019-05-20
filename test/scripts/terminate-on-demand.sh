rm -rf ~/.ssh/known_hosts
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2}
touch ~/.ssh/known_hosts

# terminate all instances
if [[ -f instances ]]; then
    aws ec2 terminate-instances --instance-ids `cat instances`
fi

# deregister slave image and delete the snapshot
if [[ -f slave_image ]]; then
    image_id=`cat slave_image`
    image_info=`aws ec2 describe-images --image-ids $image_id`
    snapshot_ids=`echo $image_info | jq .Images[].BlockDeviceMappings[].Ebs.SnapshotId | tr -d '"'`
    echo "deregister image $image_id"
    aws ec2 deregister-image --image-id $image_id
    for id in $snapshot_ids
    do
        echo "delete snapshot $id"
        aws ec2 delete-snapshot --snapshot-id $id
    done
fi

rm -rf logs exp.log instances* ips* __pycache__ slave_image *.csv *.tgz