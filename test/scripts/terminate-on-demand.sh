rm -rf ~/.ssh/known_hosts
touch ~/.ssh/known_hosts
[[ -f instances ]] || exit
instance=`cat instances`
aws ec2 terminate-instances --instance-ids $instance
