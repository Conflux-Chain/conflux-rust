#!/bin/bash

set -e

# echo python version
python3 --version

pip3 install \
    cfx-account \
    eth-utils \
    py-ecc \
    rlp \
    trie \
    coincurve \
    safe-pysha3 \
    conflux-web3==1.4.3 \
    web3 \
    jsonrpcclient==4.0.3 \
    requests \
    asyncio \
    websockets \
    pyyaml \
    numpy \
    pytest \
    pytest-xdist \
    git+https://github.com/petertdavies/ethereum-spec-evm-resolver.git@623ac4565025e72b65f45b926da2a3552041b469 \
    git+https://github.com/ethereum/execution-spec-tests.git@e04edbe1f9c0b932b628165d12af8d244e4da776
# set global solc version which is required by execution-spec-tests
solc-select use 0.8.24 --always-install

# TODO cross platform
#yum install clang snappy snappy-devel zlib zlib-devel bzip2 bzip2-devel lz4-devel
#   wget https://github.com/facebook/zstd/archive/v1.1.3.tar.gz
#   mv v1.1.3.tar.gz zstd-1.1.3.tar.gz
#   tar zxvf zstd-1.1.3.tar.gz
#   cd zstd-1.1.3
#   make && sudo make install
