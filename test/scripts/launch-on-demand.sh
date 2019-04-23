mv instances instances_old
region=us-west-1
n=$1
image="ami-06397100adf427136" # clean ubuntu 18
type="m5.xlarge"
keypair=$2
role=$3
res=`aws ec2 run-instances --region $region --image-id $image --count $n --key-name $keypair --instance-type $type --security-group-ids sg-00d427c03495a4973 --subnet-id subnet-12e70274 --block-device-mapping DeviceName=/dev/sda1,Ebs={VolumeSize=200} --tag-specifications "ResourceType=instance,Tags=[{Key=role,Value=$role},{Key=Name,Value=$type-$image}]"`
echo $res
echo $res | jq ".Instances[].InstanceId" | tr -d '"' > instances
