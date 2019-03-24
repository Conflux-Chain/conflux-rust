#!/usr/bin/env bash

ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )"/.. && pwd )"

# clean net config
rm -rf $ROOT_DIR/config

# clean db
rm -f $ROOT_DIR/db/*.log
rm -f $ROOT_DIR/db/*.sst
rm -f $ROOT_DIR/db/CURRENT
rm -f $ROOT_DIR/db/IDENTITY
rm -f $ROOT_DIR/db/LOCK
rm -f $ROOT_DIR/db/LOG*
rm -f $ROOT_DIR/db/MANIFEST*
rm -f $ROOT_DIR/db/OPTIONS-*