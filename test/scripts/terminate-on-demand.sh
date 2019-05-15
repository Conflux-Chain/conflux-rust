rm -rf ~/.ssh/known_hosts
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2}
touch ~/.ssh/known_hosts
[[ -f instances ]] || exit
instance=`cat instances`
aws ec2 terminate-instances --instance-ids $instance

rm -rf logs exp.log instances* ips* __pycache__
