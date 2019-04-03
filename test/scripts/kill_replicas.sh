#!/bin/bash
while read ip
do
    ssh -o "StrictHostKeyChecking no" $ip "killall -9 conflux" &
done < ips
wait

