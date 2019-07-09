#!/usr/bin/env bash
# This scripts requires that cargo and awscli are installed and configured, and have set nproc and nofile
source ~/.bashrc
if ! [ -x "$(command -v cargo)" ]; then
  echo 'Error: cargo is not installed.' >&2
  exit 1
fi
branch=${1:-master}

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
sudo apt install -y iotop clang git jq pssh
pip3 install prettytable

if [[ ! -d conflux-rust ]]; then
  git clone https://github.com/Conflux-Chain/conflux-rust
fi

cd conflux-rust
git reset --hard
git fetch --all
git checkout origin/$branch
cargo update
cargo build --release --features "deadlock_detection"
./dev-support/dep_pip3.sh
cd tests/scripts
cp ../../target/release/conflux throttle_bitcoin_bandwidth.sh remote_start_conflux.sh remote_collect_log.sh stat_latency_map_reduce.py ~

