#!/usr/bin/env bash
# sudo rm -rf /etc/hosts
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2}

if [[ $# -eq 0 ]]; then
    IP_NAME="PrivateIpAddress"
elif [[ $# -eq 1 ]] && [[ "$1" == "--public" ]]; then 
    IP_NAME="PublicIpAddress"
else
    echo "Invalid argument. Pass no argument to get private ips or --public for public ips."
fi

if [[ -f ips ]]; then
    mv ips ips_old
fi
touch ips
if [[ -f instances ]]
then
	instance=`cat instances`
	response=`aws ec2 describe-instances --instance-ids $instance`
	echo $response | jq ".Reservations[].Instances[].$IP_NAME" | tr -d '"' > ips_tmp
	uniq ips_tmp > ips
	rm ips_tmp
fi
echo GET `wc -l ips` IPs
ips=(`cat ips`)
for i in `seq 0 $((${#ips[@]}-1))`
do
#  echo ${ips[$i]} n$i |sudo tee -a /etc/hosts
  ssh -o "StrictHostKeyChecking no" ubuntu@${ips[$i]} "exit" &
done
wait
true
#scp ips_current lpl@blk:~/ips
#scp -i MyKeyPair.pem ips_current ubuntu@aws:~/ssd/ips
#ssh vm "./tmp.sh"
#rm ipof*
