#!/bin/bash

set -e

# --portable: build RocksDB/titan portable (no -march=native) for CI. Co-selecting
# `-p kvdb-rocksdb` (a direct rocksdb dependent) with its `portable` feature makes
# Cargo unify rocksdb/portable across the whole resolve; a bare `-p <crate>` can't
# request rocksdb/portable unless that crate itself directly depends on rocksdb.
portable_args=()
if [ "$1" = "--portable" ]; then
  portable_args=(-p kvdb-rocksdb --features kvdb-rocksdb/portable)
fi

for crate in $(grep -oP '^\s*\K[\w-]+(?=\s*=\s*{ path)' Cargo.toml); do
  printf '\n\033[1;36m    Checking individual crate %s\033[0m\n\n' "$crate"
  cargo check -p "$crate" "${portable_args[@]}"
  cargo check --tests -p "$crate" "${portable_args[@]}"
done
cargo check -p cfx-addr --no-default-features --tests
