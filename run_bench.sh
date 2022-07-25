#!/bin/bash

#python tests/extra-test-toolkits/produce_tx.py

#cargo build --release --features "client/metric-goodput" --features "amt-storage" --features "cfxcore/bypass-txpool" --target-dir target/amt-db
cargo build --release --features "client/metric-goodput" --features "cfxcore/bypass-txpool"
#cargo build --release --features "client/metric-goodput" --features "mpt-storage" --features "cfxcore/bypass-txpool" --target-dir target/mpt-db

function run {
#    python tests/extra-test-toolkits/single_bench.py --port-min 13000 --bench-keys $1 --bench-txs $2 --bench-mode normal
#    python tests/extra-test-toolkits/single_bench.py --port-min 13000 --bench-keys $KEYS --bench-txs $TXS --bench-mode slow-exec
#    python tests/extra-test-toolkits/single_bench.py --port-min 13000 --bench-keys $1 --bench-txs $2 --bench-mode less-sender
      python tests/amt-benchmark/main.py --port-min 13000 --bench-keys $1 --bench-txs $2 --bench-mode less-sender --bench-token native --metric-folder eurosys
      python tests/amt-benchmark/main.py --port-min 13000 --bench-keys $1 --bench-txs $2 --bench-mode less-sender --bench-token erc20 --metric-folder eurosys

}

#python tests/extra-test-toolkits/single_bench.py --port-min 13000 --bench-txs 100000 --bench-mode sample

function main {
#  export CONFLUX_DEV_STORAGE=amt
#  run $1 $2
#
#  export AMT_SHARD_SIZE=64
#  run $1 $2
#
#  export AMT_SHARD_SIZE=16
#  run $1 $2
#
#  unset AMT_SHARD_SIZE

  export CONFLUX_DEV_STORAGE=dmpt
  run $1 $2

#  export CONFLUX_DEV_STORAGE=mpt
#  run $1 $2

}

unset http_proxy

main "1m" "5m"
main "3m" "15m"
main "5m" "25m"
#main "10m" "30m"

#main "100k" "900k"