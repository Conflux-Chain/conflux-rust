## Security Fix

* Fix several possible node panics and excessive memory usage.

## Bug Fix

* Fix a possible execution deadlock during concurrent trace queries.
* Fix incorrect peer reputation updates during simultaneous connections.
* Fix missing block-body checks during catch-up synchronization.

## RPC Changes

* Fix `eth_createAccessList` returning empty or incorrect access lists.
* Fix a panic when tracing the genesis block.

## Improvement

* Upgrade OpenSSL to 3.5.9 in Linux builds.
* Update dependencies to fix security issues.
