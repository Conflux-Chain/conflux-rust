set -eux
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2}
SCRIPT_DIR="$( cd "$(dirname "$0")" ; pwd -P )"

if [[ $# -lt 1 ]]; then
    echo "Parameters required: <keypair> [<branch>]"
    exit 1
fi
key_pair="$1"
branch="${2:-master}"
tmp_dir="tmp_data"

if [[ -d "$tmp_dir" ]]; then
    mv $tmp_dir ${tmp_dir}_backup
fi
mkdir $tmp_dir
cd $tmp_dir
$SCRIPT_DIR/launch-on-demand.sh 1 $key_pair ${key_pair}_master 

master_ip=`cat ips`
master_id=`cat instances`
setup_script="setup_image.sh"
scp -o "StrictHostKeyChecking no" $SCRIPT_DIR/$setup_script ubuntu@$master_ip:~
ssh ubuntu@$master_ip ./$setup_script $branch

res=`aws ec2 create-image --instance-id $master_id --name ${key_pair}_slave_image --no-reboot`
echo $res|jq ".ImageId"
