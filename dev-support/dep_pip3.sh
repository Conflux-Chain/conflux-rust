#!/bin/bash

set -e

pip3 install cfx-account eth-utils py-ecc trie coincurve safe-pysha3 web3==7.4.0 py-solc-x jsonrpcclient==3.3.6 asyncio websockets pyyaml numpy


# python3 -m solcx.install v0.5.17

# TODO cross platform
#yum install clang snappy snappy-devel zlib zlib-devel bzip2 bzip2-devel lz4-devel
#   wget https://github.com/facebook/zstd/archive/v1.1.3.tar.gz
#   mv v1.1.3.tar.gz zstd-1.1.3.tar.gz
#   tar zxvf zstd-1.1.3.tar.gz
#   cd zstd-1.1.3
#   make && sudo make install
