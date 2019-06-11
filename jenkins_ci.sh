#!/bin/bash

export PATH=$HOME/.cargo/bin:$PATH
killall -q -9 conflux || echo "All conflux process killed before build and test."
./dev-support/test.sh