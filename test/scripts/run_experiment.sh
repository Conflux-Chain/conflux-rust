#!/bin/bash
shopt -s  expand_aliases
which pssh || alias pssh='parallel-ssh'
which pscp || alias pscp='parallel-scp'
{
    branch="dagger"
    n_node=50
    node_per_host=20
    block_size=4
    generation_period=10
    block_number=360
    ./launch-on-demand.sh $n_node $branch
    while true
    do
        ./list-on-demand.sh
        n=`cat ips|wc -l`
        echo Wait for $(($n_node-$n)) more instances to launch
        all=`cat instances_all|wc -l`
        if [[ $n_node -le $n ]]
        then
            break
        fi
        sleep 1
    done
    while true
    do
        n=`pscp -O "StrictHostKeyChecking no" -h ips -l lpl -p 1000 throttle_bitcoin_bandwidth.sh /home/lpl|grep FAILURE|wc -l`
        echo Wait for $n more instances to start
        if [[ $n -eq 0 ]]
        then
            break
        fi
        sleep 1
        ./ip.sh
    done

    mkdir logs/logs_tmp
    mkdir logs/logs_old
    pssh -O "StrictHostKeyChecking no" -h ips -l lpl -p 1000 -t 600 "./throttle_bitcoin_bandwidth.sh 20 $node_per_host;cd bitcoin;rm -rf test/functional;git fetch;git checkout dagger_large;git checkout -- .;git pull;make -j7;exit"
    python3 ghost_test.py $node_per_host $block_size $generation_period $block_number ips

    pssh -O "StrictHostKeyChecking no" -h ips -l lpl -p 1000 -t 600 'find /tmp -name "debug.log" |xargs tar cvfz log.tgz'
    for i in `cat ips`
    do
        scp -o "StrictHostKeyChecking no" lpl@$i:~/log.tgz logs/logs_tmp/$i.tgz &
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
    ./terminate-on-demand.sh
    for f in `ls logs/logs_tmp/*.tgz`
    do
        tar_dir=${f%.tgz}
        mkdir $tar_dir
        tar xzf $f -C $tar_dir
    done
    logname=$branch-$n_node-$node_per_host-$block_size-$generation_period-$block_number-`date +%s`
    echo $logname
    cp output logs/logs_tmp
    mv logs/logs_tmp logs/logs_old/"$logname"
    head -n -$n_node ~/.ssh/known_hosts |tee ~/.ssh/known_hosts > /dev/null
    python3 compute_dagger_latency.py logs/logs_old/"$logname" $block_number $generation_period
    exit
} 2>&1 | tee output
