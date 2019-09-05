#!/bin/bash

set -e

function install() {
	if [ "`pip3 show $1`" =  "" ]; then
		pip3 install $1
	fi
}

install eth-utils
install rlp
install py_ecc
install coincurve
install pysha3
install trie
install web3
install easysolc
install jsonrpcclient

# TODO cross platform
#yum install clang snappy snappy-devel zlib zlib-devel bzip2 bzip2-devel lz4-devel
#   wget https://github.com/facebook/zstd/archive/v1.1.3.tar.gz
#   mv v1.1.3.tar.gz zstd-1.1.3.tar.gz
#   tar zxvf zstd-1.1.3.tar.gz
#   cd zstd-1.1.3
#   make && sudo make install