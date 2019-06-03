#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$(dirname "$0")"/.. ; pwd -P )"

if [ $# -lt 2 ]; then
    echo "Parameters required: <resource_group> <instance_count>"
    exit 1
fi

group=$1
if [ "`az group exists -n $group`" = "false" ]; then
    echo "group $group not found."
    exit 1
fi

num_slaves=$2
location="eastasia"
template_group="conflux-experiment"
subscription_id=`az account show --query id -o tsv`

echo "launch $2 slave VMs ..."
az vmss create -n expvmss -l $location -g $group --instance-count $num_slaves \
    --admin-username ubuntu --generate-ssh-key \
    --vm-sku Standard_D4s_v3 --image exp-slave-image

echo "retrieve private IPs of slave VMs ..."
while true
do
    az vmss nic list -g $group --vmss-name expvmss --query [].ipConfigurations[0].privateIpAddress -o tsv > ips
    if [[ $num_slaves -eq `cat ips | wc -l`  ]]; then
        break
    fi
done