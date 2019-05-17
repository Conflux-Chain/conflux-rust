rm -rf ~/.ssh/known_hosts
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2}
touch ~/.ssh/known_hosts

if [[ -f instances ]]; then
    aws ec2 terminate-instances --instance-ids `cat instances`
fi

if [[ -f slave_image ]]; then
    aws ec2 deregister-image --image-id `cat slave_image`
fi

rm -rf logs exp.log instances* ips* __pycache__ slave_image *.csv *.tgz