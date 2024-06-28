#!/bin/bash

set -e

function install() {
	if [ "`pip3 show ${1%%=*}`" =  "" ]; then
		pip3 install $1
	fi
}

install git+https://github.com/conflux-fans/cfx-account.git@v1.1.0-beta.2 # install cfx-account lib and prepare for CIP-1559 tests
install eth-utils
install rlp==1.2.0
install py-ecc==5.2.0
install coincurve==19.0.1
install pysha3
install trie==1.4.0
install web3==5.31.1
install py-solc-x
install jsonrpcclient==3.3.6
install asyncio
install websockets
install pyyaml
install numpy

python3 -m solcx.install v0.5.17

# TODO cross platform
#yum install clang snappy snappy-devel zlib zlib-devel bzip2 bzip2-devel lz4-devel
#   wget https://github.com/facebook/zstd/archive/v1.1.3.tar.gz
#   mv v1.1.3.tar.gz zstd-1.1.3.tar.gz
#   tar zxvf zstd-1.1.3.tar.gz
#   cd zstd-1.1.3
#   make && sudo make install
