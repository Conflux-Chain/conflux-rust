# This scripts requires that cargo is installed
source ~/.bashrc
if ! [ -x "$(command -v cargo)" ]; then
  echo 'Error: cargo is not installed.' >&2
  exit 1
fi
branch=${1:-master}
sudo apt install -y iotop clang git

if [[ ! -d conflux-rust ]]; then
  git clone https://github.com/Conflux-Chain/conflux-rust
fi

cd conflux-rust
git pull
git checkout $branch
cargo update
cargo build --release
cd test/scripts
cp ../../target/release/conflux throttle_bitcoin_bandwidth.sh remote_start_conflux.sh remote_collect_log.sh stat_latency_map_reduce.py ~

cd ~
./throttle_bitcoin_bandwidth.sh 20 30
ls /sys/fs/cgroup/net_cls