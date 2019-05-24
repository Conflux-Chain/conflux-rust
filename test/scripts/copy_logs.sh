#!/bin/bash

set -e

log_dir=logs

rm -rf $log_dir
mkdir -p $log_dir/logs_tmp


#parallel-ssh -O "StrictHostKeyChecking no" -h ips -p 400 -t 600 'find /tmp/conflux_test_* -name "conflux.log" | xargs tar cvfz log.tgz'
parallel-ssh -O "StrictHostKeyChecking no" -h ips -p 400 -t 600 "./remote_collect_log.sh"
for i in `cat ips`
do
    scp -o "StrictHostKeyChecking no" ubuntu@$i:~/log.tgz $log_dir/logs_tmp/$i.tgz &
done
while true
do
    n=`ps -ef|grep [s]cp|grep tgz|grep -v grep|wc -l`
    if [ $n -eq 0 ]
    then
        break
    fi
    echo $n remaining to download log
    sleep 1
done


for f in `ls $log_dir/logs_tmp/*.tgz`
do
    tar_dir=${f%.tgz}
    mkdir $tar_dir
    tar xzf $f -C $tar_dir
    rm $f
done
