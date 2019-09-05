#!/usr/bin/env bash

name_list="$(az vm list --query "[?tags.exp == 'ReplayEth']" | jq '.[].name')"
rm ip_list.txt
for name in $name_list
do
    stripped_name=$(echo "$name" | tr -d '"')
    ip="$(az vm show -d -g conflux_inner_test -n ${stripped_name} --query publicIps -o tsv)"
    echo $ip >> ip_list.txt
done