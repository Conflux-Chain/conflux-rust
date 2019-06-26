#!/bin/bash

version="release"

SCRIPT_DIR=`dirname "${BASH_SOURCE[0]}"`
ROOT_DIR="$( cd $SCRIPT_DIR/.. && pwd )"
export CARGO_TARGET_DIR=$ROOT_DIR/build
cd "$( dirname "${BASH_SOURCE[0]}" )"
RUSTFLAGS=-g cargo build --release
while read ip
do
    #ssh -o "StrictHostKeyChecking no" $ip "cd conflux-rust; cargo build" &
    scp -o "StrictHostKeyChecking no" $CARGO_TARGET_DIR/$version/conflux $ip:~/conflux-rust/target/debug/conflux &
done < ips
wait

