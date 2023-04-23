#!/bin/bash

function build {
  # --features "pprof-profile"
  # --features cfxcore/light-hash-storage

  export common_features='--features client/metric-goodput --features cfxcore/bypass-txpool'

  # LVMT
  cargo build --release $common_features --features "lvmt-storage" --target-dir target/lvmt-db
  # RAW
  cargo build --release $common_features --features "raw-storage" --target-dir target/raw-db
  # OpenEthereum's MPT
  cargo build --release $common_features --features "mpt-storage" --target-dir target/mpt-db
  # LMPTs
  cargo build --release --features "client/metric-goodput" --features "cfxcore/bypass-txpool" --features "cfxcore/storage-dev"
}

function run {
  python3 tests/asb-e2e/main.py --port-min 23000 --bench-keys $1 --bench-txs $2 --bench-token native --metric-folder osdi23
  python3 tests/asb-e2e/main.py --port-min 23000 --bench-keys $1 --bench-txs $2 --bench-token erc20 --metric-folder osdi23
}


function main {
  export CONFLUX_DEV_STORAGE=lvmt
  run $1 $2

  export LVMT_SHARD_SIZE=64
  run $1 $2
  unset LVMT_SHARD_SIZE

  export LVMT_SHARD_SIZE=16
  run $1 $2
  unset LVMT_SHARD_SIZE

  export CONFLUX_DEV_STORAGE=lmpts
  run $1 $2

  export CONFLUX_DEV_STORAGE=mpt
  run $1 $2

  export CONFLUX_DEV_STORAGE=raw
  run $1 $2

}

unset http_proxy

if [[ $1 == "build" ]]; then
  build
else
  # export LIGHT_HASH=1
  main "1m" "1m"
  main "3m" "9m"
  main "5m" "15m"
  #main "10m" "30m"
fi