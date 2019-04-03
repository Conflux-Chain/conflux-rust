#!/bin/bash
version="release"
cd "$( dirname "${BASH_SOURCE[0]}" )"
RUSTFLAGS=-g cargo build --release
while read ip
do
    #ssh -o "StrictHostKeyChecking no" $ip "cd conflux-rust; cargo build" &
    scp -o "StrictHostKeyChecking no" ~/conflux-rust/target/$version/conflux $ip:~/conflux-rust/target/debug/conflux &
done < ips
wait

