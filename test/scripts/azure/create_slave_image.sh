#!/bin/bash

set -e

if [ $# -lt 1 ]; then
    echo "Parameters required: <resource_group> [<branch>]"
    exit 1
fi

SCRIPT_DIR="$( cd "$(dirname "$0")"/.. ; pwd -P )"

group=$1
if [ "`az group exists -n $group`" = "true" ]; then
    echo "group $group already exists, please specify another group name."
    exit 1
fi

location="eastasia"
template_group="conflux-experiment"
subscription_id=`az account show --query id -o tsv`
branch="${2:-master}"

echo "create resource group ..."
az group create -l $location -n $group

echo "create master VM from image ..."
az vm create -l $location -g $group -n exp-master \
    --admin-username ubuntu --generate-ssh-keys \
    --nsg $template_group-nsg --size Standard_D4s_v3 \
    --image /subscriptions/$subscription_id/resourceGroups/$template_group/providers/Microsoft.Compute/images/$template_group-image \
    --no-wait

echo "create slave VM to make image ..."
az vm create -l $location -g $group -n exp-slave \
    --admin-username ubuntu --generate-ssh-keys \
    --nsg $template_group-nsg --size Standard_D4s_v3 \
    --image /subscriptions/$subscription_id/resourceGroups/$template_group/providers/Microsoft.Compute/images/$template_group-image

echo "setup on slave VM ..."
slave_public_ip=`az vm show -g $group -n exp-slave -d --query publicIps -o tsv`
setup_script="setup_image.sh"
scp -o "StrictHostKeyChecking no" $SCRIPT_DIR/$setup_script ubuntu@$slave_public_ip:~
ssh ubuntu@$slave_public_ip "source ~/.cargo/env; ./$setup_script $branch"

# create slave image
echo "create slave image ..."
echo "[1/3] deallocate VM ..."
az vm deallocate -g $group -n exp-slave
echo "[2/3] generalize VM ..."
az vm generalize -g $group -n exp-slave
echo "[3/3] create image ..."
az image create -l $location -g $group -n exp-slave-image --source exp-slave

echo "wait for master VM to be started ..."
az vm wait -g $group -n exp-master --created

master_public_ip=`az vm show -g $group -n exp-master -d --query publicIps -o tsv`
echo $master_public_ip > ips_master