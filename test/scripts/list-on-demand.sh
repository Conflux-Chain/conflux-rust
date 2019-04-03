mv instances instances_old
mv instances_all instances_all_old
#mv requests requests_old
#responce=`aws ec2 describe-spot-instance-requests`
#requests=`echo "$responce"| grep INSTANCE |grep active| awk '{print $7}'`
#for i in ${requests[*]}
#do
#    echo $i >> requests
#done

res=`aws ec2 describe-instances --filters Name=tag:owner,Values=lpl Name=tag:role,Values=conflux_client Name=instance-state-name,Values=running`
instances=`echo "$res"|grep INSTANCES|awk '{print $7}'`
for i in ${instances[*]}
do
    echo $i >> instances
    echo $i >> instances_all
done
res=`aws ec2 describe-instances --filters Name=tag:owner,Values=lpl Name=tag:role,Values=conflux_client Name=instance-state-name,Values=pending`
instances=`echo "$res"|grep INSTANCES|awk '{print $7}'`
for i in ${instances[*]}
do
    echo $i >> instances_all
done
#echo "$res"|grep STATE|grep running > state
./ip.sh
