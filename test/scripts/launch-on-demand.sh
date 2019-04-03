mv instances instances_old
region=us-west-1
n=$1
image="ami-0dd9502e04ffcc162"
type="m5.large"
keypair="bo.qiu.test"
res=`aws ec2 run-instances --region $region --image-id $image --count $n --key-name $keypair --instance-type $type --security-group-ids sg-00d427c03495a4973 --subnet-id subnet-3a675661 --block-device-mapping DeviceName=/dev/xvda,Ebs={VolumeSize=100} --tag-specifications "ResourceType=instance,Tags=[{Key=owner,Value=lpl},{Key=role,Value=conflux_client},{Key=Name,Value=$type-$image}]"`
#res=`aws ec2 run-instances --image-id $image --count $n --key-name $keypair --instance-type $type --security-group-ids sg-0d9f2b083ae9853d9 --subnet-id subnet-322c3f55 --tag-specifications "ResourceType=instance,Tags=[{Key=owner,Value=lpl},{Key=role,Value=conflux_control},{Key=Name,Value=$type-control}]"`
echo "$res"|grep INSTANCES|awk '{print $7}' > instances
