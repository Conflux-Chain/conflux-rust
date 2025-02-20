#!/bin/bash

set -e

pip3 install \
    cfx-account \
    eth-utils \
    py-ecc \
    rlp \
    trie \
    coincurve \
    safe-pysha3 \
    conflux-web3==1.4.0b5 \
    web3 \
    jsonrpcclient==4.0.3 \
    requests \
    asyncio \
    websockets \
    pyyaml \
    numpy \
    pytest \
    pytest-xdist

# TODO cross platform
#yum install clang snappy snappy-devel zlib zlib-devel bzip2 bzip2-devel lz4-devel
#   wget https://github.com/facebook/zstd/archive/v1.1.3.tar.gz
#   mv v1.1.3.tar.gz zstd-1.1.3.tar.gz
#   tar zxvf zstd-1.1.3.tar.gz
#   cd zstd-1.1.3
#   make && sudo make install
