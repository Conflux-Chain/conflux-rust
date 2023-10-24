#!/bin/bash

export folder="tos23"
export common_features='--features client/metric-goodput --features cfxcore/bypass-txpool'
function cgenv {
  $@
}

function build {
  # LVMT
  cargo build --release $common_features --features "lvmt-storage" --target-dir target/lvmt-db
  # RAW
  cargo build --release $common_features --features "raw-storage" --target-dir target/raw-db
  # OpenEthereum's MPT
  cargo build --release $common_features --features "mpt-storage" --target-dir target/mpt-db
  # RainBlock's MPT
  cargo build --release $common_features --features "rain-storage" --target-dir target/rain-db
  # LMPTs
  cargo build --release --features "client/metric-goodput" --features "cfxcore/bypass-txpool" --features "cfxcore/storage-dev"  
}

function clear_caches {
  if ! alias cgenv 2>/dev/null | grep -q "^alias cgenv=''"; then
    sudo sysctl -w vm.drop_caches=3
  fi
}

function run {
  clear_caches
  cgenv python3 tests/asb-e2e/main.py --port-min 23000 --bench-keys $1 --bench-txs $2 --bench-token native --metric-folder $folder
  clear_caches
  cgenv python3 tests/asb-e2e/main.py --port-min 23000 --bench-keys $1 --bench-txs $2 --bench-token erc20 --metric-folder $folder
  clear_caches
  cgenv python3 tests/asb-e2e/main.py --port-min 23000 --bench-keys $1 --bench-txs $1 --bench-token erc20 --bench-mode uniswap --metric-folder $folder
}


function main {
  export CONFLUX_DEV_STORAGE=rain
  run "$@"

  export CONFLUX_DEV_STORAGE=lvmt
  run "$@"

  export LVMT_SHARD_SIZE=64
  run "$@"
  unset LVMT_SHARD_SIZE

  export LVMT_SHARD_SIZE=16
  run "$@"
  unset LVMT_SHARD_SIZE

  export CONFLUX_DEV_STORAGE=lmpts
  run "$@"

  export CONFLUX_DEV_STORAGE=mpt
  run "$@"

  export CONFLUX_DEV_STORAGE=raw
  run "$@"
}

unset http_proxy

if [[ $1 == "build" ]]; then
  build
else
  # export LIGHT_HASH=1
  main "1m" "3m"
  main "3m" "9m"
  main "5m" "15m"
fi