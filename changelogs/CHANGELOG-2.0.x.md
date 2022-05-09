# 2.0.3

# 2.0.2

## Improvements

### RPC Improvements
- Improve the performance of `eth_getLogs`.
- Add a new RPC `eth_getAccountPendingTransactions` to get pending transactions by address, also return the first pending transaction's pending reason
- Support WebSockets for eth APIs
- Support block hash param for `eth_call` (EIP1898)
- `cfx_call`, `cfx_estimateGasAndCollateral`, `eth_call`, and `eth_estimate` will respect `from`'s balance if passed, if balance is not enough will return error. If from is not passed then use a random one, which's balance will be very big.

### Transaction Pool Improvements
- Set the minimum gas price to 1 GDrip by default for packing transaction

### Storage Improvement
- Improve the snapshot copy-on-write merging performance on XFS file systems.

## Bug Fixes
- Fix trace validity for transactions reverted in the top checkpoint.
- Fix phantom trace length mismatch issue with failed transactions.
- Fix a possible underflow crash in `eth_estimateGas`.

# 2.0.1

## Improvements

### RPC Improvements
- Report error in `cfx_getLogs` and `eth_getLogs` if `get_logs_filter_max_limit` is configured but the query would return more logs. The previous behavior of `cfx_getLogs` was to silently truncate the result. The previous behavior of `eth_getLogs` was to raise an error when `filter.limit` is too low, regardless of how many logs the query would result in.
- `eth_gasPrice` now estimate gas prices accurately instead of returning a fixed value.
- Support phantom transactions and return correct fields in eSpace `trace` RPCs.
- Add fields `valid` and `createType` for eSpace `trace` RPCs.
- Add RPC `rpc_methods` to return all available methods and `rpc_modules` to return all RPC modules.
- Add `totalEspaceTokens` in the response of `cfx_getSupplyInfo`.
- Add local RPCs `pos_start_voting`, `pos_stop_voting`, and `pos_voting_status`. Check #2438 for details.

### Configuration Improvements
- Allow PoS voting nodes to have running backups. #2438 includes an introduction.
- Add config parameter `get_logs_filter_max_block_number_range` for limiting the maximum gap between `from_block` and `to_block` during Core space log filtering (`cfx_getLogs`). Note: eSpace blocks correspond to epochs in Core space, so the range in `eth_getLogs` can be limited using `get_logs_filter_max_epoch_range`.
- Add config parameter `min_phase_change_normal_peer_count` to set the number of normal-phase peers needed for phase change. The default value is set to 3 to make it more robust.
- Add environment variable `CFX_POS_KEY_ENCRYPTION_PASSWORD` to configure pos key encryption password.

### Transaction Pool Improvements
- Allow pending transactions to be replaced unconditionally after 200000 epochs.

## Bug Fixes
- Fix an issue that phantom transactions may have the same hash. Now all phantom transactions have different hashes after this fix.
- Create PoS log file directory if it does not exist. 
- Fix a panic issue when the node is started with `stdout` unavailable.
- Fix an issue that an old transaction is not replaced according to a higher `epoch_height`.

