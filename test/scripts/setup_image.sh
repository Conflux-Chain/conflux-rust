#!/usr/bin/env bash
# This scripts requires that cargo and awscli are installed and configured
source ~/.bashrc
if ! [ -x "$(command -v cargo)" ]; then
  echo 'Error: cargo is not installed.' >&2
  exit 1
fi
branch=${1:-master}

# Wait for apt to be unlocked
i=0
while fuser /var/lib/dpkg/lock >/dev/null 2>&1 ; do
    case $(($i % 4)) in
        0 ) j="-" ;;
        1 ) j="\\" ;;
        2 ) j="|" ;;
        3 ) j="/" ;;
    esac
    echo -en "\r[$j] Waiting for other software managers to finish..."
    sleep 0.5
    ((i=i+1))
done

sudo apt update
sudo apt install -y iotop clang git jq pssh
pip3 install prettytable

if [[ ! -d conflux-rust ]]; then
  git clone https://github.com/Conflux-Chain/conflux-rust
fi

cd conflux-rust
git reset --hard
git checkout $branch
git pull
cargo update
cargo build --release
./dev-support/dep_pip3.sh
cd test/scripts
cp ../../target/release/conflux throttle_bitcoin_bandwidth.sh remote_start_conflux.sh remote_collect_log.sh stat_latency_map_reduce.py ~

cd ~
./throttle_bitcoin_bandwidth.sh 20 30
ls /sys/fs/cgroup/net_cls