#!/usr/bin/env bash
# This scripts requires that cargo and awscli are installed and configured, and have set nproc and nofile
source ~/.bashrc
if ! [ -x "$(command -v cargo)" ]; then
  echo 'Error: cargo is not installed.' >&2
  exit 1
fi
branch=${1:-master}
repo="${2:-https://github.com/Conflux-Chain/conflux-rust}"

apt_wait () {
  while sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 ; do
    sleep 1
  done
  while sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1 ; do
    sleep 1
  done
  if [ -f /var/log/unattended-upgrades/unattended-upgrades.log ]; then
    while sudo fuser /var/log/unattended-upgrades/unattended-upgrades.log >/dev/null 2>&1 ; do
      sleep 1
    done
  fi
}
sudo apt update
echo "Wait for apt to be unlocked"
apt_wait
sudo apt install -y iotop iftop htop clang git jq pssh libsqlite3-dev xutils-dev cmake pkg-config libssl-dev
pip3 install prettytable
pip3 install jsonrpcclient

sudo apt install -y linux-tools-common
sudo apt install -y linux-tools-`uname -r`
cargo install flamegraph
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid

if [[ ! -d conflux-rust ]]; then
  git clone https://github.com/Conflux-Chain/conflux-rust
fi

cd conflux-rust
git reset --hard
if [ $repo == "https://github.com/Conflux-Chain/conflux-rust" ]; then
    repo="origin"
else
    git remote add downstream $repo
    repo="downstream"
fi

git fetch --all
git checkout $repo/$branch
export RUSTFLAGS="-g" && cargo build --release #--features "deadlock_detection"
./dev-support/dep_pip3.sh
cd tests/scripts
wget https://s3-ap-southeast-1.amazonaws.com/conflux-test/genesis_secrets.txt
cp ../../target/release/conflux throttle_bitcoin_bandwidth.sh remote_start_conflux.sh remote_collect_log.sh stat_latency_map_reduce.py genesis_secrets.txt ~

# Remove process number limit.
echo "LABEL=cloudimg-rootfs   /        ext4   defaults,noatime,nodiratime,barrier=0       0 0" > fstab
sudo cp fstab /etc/fstab
echo "ulimit -n 65535" >> ~/.profile
# Cannot assign a value more than half of `/proc/sys/kernel/threads-max`, which is about 120,000.
echo "ulimit -u 60000" >> ~/.profile
echo "*            -          nproc     65535 " | sudo tee -a /etc/security/limits.conf
echo "*            -          nfile     65535 " | sudo tee -a /etc/security/limits.conf
echo "DefaultTasksMax=65535" | sudo tee -a /etc/systemd/system.conf
sudo mkdir -p /etc/systemd/logind.conf.d
echo "[Login] \nUserTasksMax=infinity" |sudo tee -a /etc/systemd/logind.conf.d/override.conf
