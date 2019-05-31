#!/bin/bash

# Install Rust and dependent libs/tools
curl https://sh.rustup.rs -sSf | sh
source ~/.cargo/env
sudo apt install -y iotop clang git jq pssh python3-pip
pip3 install prettytable
pip3 install python-dateutil

# Clone code and build in release mode
git clone https://github.com/Conflux-Chain/conflux-rust
cd conflux-rust
./dev-support/dep_pip3.sh
cargo build --release

# change limits for experiment
echo "* soft nofile 65535" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65535" | sudo tee -a /etc/security/limits.conf