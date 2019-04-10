mv instances instances_old
region=us-west-1
n=$1
image="ami-06397100adf427136" # clean ubuntu 18
type="m5.xlarge"
keypair=$2
role=$3
res=`aws ec2 run-instances --region $region --image-id $image --count $n --key-name $keypair --instance-type $type --security-group-ids sg-00d427c03495a4973 --subnet-id subnet-3a675661 --block-device-mapping DeviceName=/dev/xvda,Ebs={VolumeSize=100} --tag-specifications "ResourceType=instance,Tags=[{Key=role,Value=$role},{Key=Name,Value=$type-$image}]"`
echo $res | jq ".Instances[].InstanceId" | tr -d '"' > instances
