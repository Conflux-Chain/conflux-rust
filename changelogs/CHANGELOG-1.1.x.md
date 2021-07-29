# 1.1.5

## Improvements

### RPC Improvements
- Fix incorrect responses of `cfx_getBlockRewardInfo`. If the node needs to serve this RPC, it needs to clear all data and resync the chain.
- Simplify EVM revert reason in RPC responses. This may cause incompatible issues if the user was decoding the error messages manually.
- Add new RPC `cfx_getBlockByBlockNumber`.
- Add `blockNumber` to the returned JSON object in `cfx_getBlockByHash`, `cfx_getBlockByEpochNumber`, and `cfx_getBlockByHashWithPivotAssumption`.
- Accept pivot hash in `cfx_getEpochReceipts`.
- Raise error in `cfx_getBlockByHashWithPivotAssumption` if the provided block hash does not belong to the provided epoch.
- Fix returnData format of CallResult.
- Fix incorrect `firstTxStatus` response of `cfx_getAccountPendingTransactions` if `start_nonce` is provided.
- Update `cfx_getCode` so that it returns an empty hex `0x` if the account does not exist instead of raising an error.

### Configuration Improvement
- Add `persist_block_number_index` to persist block number indices. It allows responding to block-number-related RPC requests for old epochs.
- Add `storage_max_open_mpt_count` to configure maximal number of opened MPT.


# 1.1.4

## Improvements

### RPC Improvements
- Add a new RPC `cfx_getAccountPendingTransactions` to get pending transactions of a given account.
- Make VM tracer records reasons for a fail execution. 
- Make `cfx_estimateGasAndCollateral` return an error stack in case an error happens in sub-call.
- Use random miner address in virtual calls (`cfx_call` and `cfx_estimateGasAndCollateral`) 
    instead of a special null address.

### Configuration Improvements
- Allow setting maximum WebSocket response payload size using `jsonrpc_ws_max_payload_bytes`. The default is 30MB.

## Bug fixes
- Fix a bug that causes repacking useless transactions.
- Fix a bug that causes the configuration `sync_state_starting_epoch` not effective on archive nodes.
- Fix a bug that may make `cfx_getStatus` return unexpected error.


# 1.1.3

## Improvements

### RPC Improvements
- Include `blockHash`, `epochHash`, `epochNumber`, `transactionHash`, and `transactionPosition` for trace RPCs.
  Note that the data format returned by `trace_block` is incompatible with old versions.
- Add new field `offset` in log filters used in `cfx_getLogs`.
  If specified, the response will skip the **last** `offset` logs.
  For instance, with 10 matching logs (`0..9`) and `offset=0x1, limit=0x5`, the response will contain logs `4..8`.
  Note: Even if you specify `offset`, the corresponding logs still need to be processed by the node,
  so a filter with `offset=10000, limit=10` has about the same performance as a filter with `offset=0, limit=100010`.
- Add a new parameter `subscription_epoch` to the `epochs` pubsub.
  The supported values are `"latest_mined"` (default) and `"latest_state"`.
- Add `cfx_getAccountPendingInfo` to get pending transaction info for some account for better investigating pending tx problems.

### Configuration Improvements
- Allow immediately packing sent transactions in `dev` mode by keeping `dev_block_interval_ms` unset.
  Note that setting `dev_block_interval_ms` will disable this immediate packing and generate blocks only periodically.
### Performance Improvements
- Optimize the state implementation for better cache performance.

### Bug fix
- Fix a bug that makes running nodes in `dev` mode not generate blocks automatically.

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
- Add new trace RPC `trace_transaction`.
- Use hex encoding for the returned bytes in trace-related RPCs.
- Add new fields `latestCheckpoint`, `latestConfirmed`, and `latestState` in `cfx_getStatus`.
- Improve some RPC error reporting.
### Performance Optimization
- Reduce the memory usage for maintaining more snapshots with the configuration `additional_maintained_snapshot_count`.
## Bug Fixes
- Fix a possible OOM error when a full node is catching up.
- Fix a possible OOM error in transaction pool when an archive node is catching up.
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