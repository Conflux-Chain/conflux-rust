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
    conflux-web3==1.4.0b5 \
    web3 \
    jsonrpcclient==4.0.3 \
    requests \
    asyncio \
    websockets \
    pyyaml \
    numpy \
    pytest \
    pytest-xdist \
    git+https://github.com/ethereum/execution-spec-tests.git@65d64c328955aef518a9f6701c64f553cabd52a2

################################################################################
# temporary solution to use eip7702 signing from viem implementation
# as upstream web3.py does not support it yet
#
# Will remove it and switch to python implementation after web3.py supports it

# set server path to fix ci issue
export PATH="/home/ubuntu/.nvm/versions/node/v20.18.3/bin:$PATH"
cd integration_tests/test_framework/util/eip7702/viem_scripts && npm install &&cd ../../../../../

# TODO cross platform
#yum install clang snappy snappy-devel zlib zlib-devel bzip2 bzip2-devel lz4-devel
#   wget https://github.com/facebook/zstd/archive/v1.1.3.tar.gz
#   mv v1.1.3.tar.gz zstd-1.1.3.tar.gz
#   tar zxvf zstd-1.1.3.tar.gz
#   cd zstd-1.1.3
#   make && sudo make install
