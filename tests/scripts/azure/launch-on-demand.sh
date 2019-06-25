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
# We need an extra SSD data disk to store data because the OS or Temporary disk in azure has very limited throughput
# 1024GB disk of Premium_LRS is supposed to provide 200MB/s throughput and 5000 IOPS
az vmss create -n expvmss -l $location -g $group --instance-count $num_slaves \
    --admin-username ubuntu --generate-ssh-key \
    --vm-sku Standard_D4s_v3 --image exp-slave-image \
    --data-disk-sizes-gb 1024 --storage-sku Premium_LRS --upgrade-policy-mode automatic

# Mount new data disk to /tmp
az vmss extension set \
  --publisher Microsoft.Azure.Extensions \
  --version 2.0 \
  --name CustomScript \
  --resource-group $group \
  --vmss-name expvmss \
  --settings '{"commandToExecute":"mkfs.ext4 /dev/sdc; rm -rf /tmp; mkdir /tmp; mount /dev/sdc /tmp; chmod 777 /tmp"}'
az vmss update -n expvmss -g $group

echo "retrieve private IPs of slave VMs ..."
while true
do
    az vmss nic list -g $group --vmss-name expvmss --query [].ipConfigurations[0].privateIpAddress -o tsv > ips
    if [[ $num_slaves -eq `cat ips | wc -l`  ]]; then
        break
    fi
done
