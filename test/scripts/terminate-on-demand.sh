rm -rf ~/.ssh/known_hosts
region=us-west-2
touch ~/.ssh/known_hosts
[[ -f instances ]] || exit
instance=`cat instances`
aws ec2 terminate-instances --region $region --instance-ids $instance
