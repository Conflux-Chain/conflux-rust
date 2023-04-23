#!/bin/bash

#python tests/extra-test-toolkits/produce_tx.py

function build {
  #--features "pprof-profile"

  export common_features='--features client/metric-goodput --features cfxcore/bypass-txpool --features cfxcore/light-hash-storage'
  cargo build --release $common_features --features "amt-storage" --target-dir target/amt-db
  cargo build --release $common_features --features "raw-storage" --target-dir target/raw-db
  cargo build --release $common_features --features "mpt-storage" --target-dir target/mpt-db

  cargo build --release --features "client/metric-goodput" --features "cfxcore/bypass-txpool" --features "cfxcore/storage-dev"
}

function run {
  python tests/amt-benchmark/main.py --port-min 23000 --bench-keys $1 --bench-txs $2 --bench-mode less-sender --bench-token native --metric-folder oakland-l
  python tests/amt-benchmark/main.py --port-min 23000 --bench-keys $1 --bench-txs $2 --bench-mode less-sender --bench-token erc20 --metric-folder oakland-l

}

#python tests/extra-test-toolkits/single_bench.py --port-min 23000 --bench-txs 100000 --bench-mode sample

function main {
  # export CONFLUX_DEV_STORAGE=amt
  # run $1 $2

  # export AMT_SHARD_SIZE=64
  # run $1 $2
  # unset AMT_SHARD_SIZE

  # export AMT_SHARD_SIZE=16
  # run $1 $2
  # unset AMT_SHARD_SIZE

  export CONFLUX_DEV_STORAGE=dmpt
  run $1 $2

  # export CONFLUX_DEV_STORAGE=mpt
  # run $1 $2

  # export CONFLUX_DEV_STORAGE=raw
  # run $1 $2

}

unset http_proxy

if [[ $1 == "build" ]]; then
  build
else
  # export LIGHT_HASH=1
  # main "1m" "3m"
  main "3m" "9m"
  main "5m" "15m"
  #main "10m" "30m"
fi

#    python tests/extra-test-toolkits/single_bench.py --port-min 13000 --bench-keys $1 --bench-txs $2 --bench-mode normal
#    python tests/extra-test-toolkits/single_bench.py --port-min 13000 --bench-keys $KEYS --bench-txs $TXS --bench-mode slow-exec
#    python tests/extra-test-toolkits/single_bench.py --port-min 13000 --bench-keys $1 --bench-txs $2 --bench-mode less-sender
