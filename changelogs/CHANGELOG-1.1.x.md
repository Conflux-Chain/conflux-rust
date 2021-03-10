# 1.1.3
## Improvements
- Add new trace RPC `trace_transaction`.

# 1.1.2

## Improvements

### Configuration Improvements
- Change the default node type to `full` node instead of `archive` node. And allow setting the node type in the
  configuration file with the entry `node_type`.
- Add parameters to independently configure the garbage collection time of different kinds of data (like receipts,
  transactions, block traces, state, e.t.c.). Check the `additional_maintained_*` entries in `run/tethys.toml`.
- If `block_db_dir` or `netconf_dir` is not set, put the default directory in the one configured with `conflux_data_dir`.
  The old behavior is to be put in the hard-coded `./blockchain_data`.
- Add a parameter `public_rpc_apis` to control the publicly available RPC interface sets. 
  The access to `test` and `debug` RPCs is no longer related to `mode`.
- Remove the parameter `enable_tracing` because it has been included in the new `public_rpc_apis`.

### RPC Improvements
- Add new local RPC `cfx_getEpochReceipts` to allow querying receipts based on an epoch number.
- Add new trace RPC `trace_filter` to allow querying traces based on epochs/types/offset.
- Add new fields `latestCheckpoint`, `latestConfirmed`, and `latestState` in `cfx_getStatus`.
- Improve some RPC error reporting.
  
### Performance Optimization
- Reduce the memory usage for maintaining more snapshots with the configuration `additional_maintained_snapshot_count`.
  
## Bug Fixes
- Fix a possible OOM error when a full node is catching up.
- Return correct `block_number` in `cfx_getStatus`.
- Fix a bug that makes the configuration `mining_author` require extra quotes to use a CIP-37 base32 address.
- Fix a bug that the block traces may be incorrect if the pivot chain switches frequently.

# 1.1.1

## Incompatible Changes
- CIP-37: Conflux to shift to base32 address format. The hex address format similar to Ethereum is deprecated in rpc interactions to full node.

## Improvements

- Reduce delay in logs pub-sub; now we send logs immediately after they become available.
- Implement Execution Trace functionality. It includes detailed call/create/return/internal_transfer events being triggered by a transfer. Inspecting the trace information will enable the applications like conflux-scan to be able to track all transfers of CFX accurately. 
- Support CIP-37 address format in `mining_author` configuration.
- Include `networkId` in `cfx_getStatus` response.
- Include `address` in `RpcAccount`.
- New RPC `cfx_getSupplyinfo` to get the total CFX supply and the circulating CFX supply.

# 1.1.0

## Incompatible changes

- CIP-38: Reduce the block base reward to 2 CFX from the epoch number 3,615,000.
- CIP-39: Blocks from the height 3,615,000 (included) are required to set the first element of their `custom` field in the header to `[1]`.

## Improvements
- Return the `custom` field in the block header for related RPCs (`cfx_getBlockByHash`, `cfx_getBlockByHashWithPivotAssumption`, `cfx_getBlockByEpochNumber`).
