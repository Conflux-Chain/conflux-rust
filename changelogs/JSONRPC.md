# JSON-RPC CHANGELOG

## v2.3.0

- Add `cfx_getCollateralInfo` to return chain collateral info.
- `cfx_getSponsorInfo` return data add two more fields: `usedStoragePoints` and `availableStoragePoints`. 
- Fix the hex encoding of PoS keys and signatures in pos RPCs.
- Return both compressed and uncompressed BLS public keys in PoS ledger info

## v2.2.5
- Use hex format for `pos` RPC data.
- Add RPC `pos_getLedgerInfoByBlockNumber` and `pos_getLedgerInfoByEpochAndRound` to get PoS ledger infos.
- Add `debug_getEpochReceiptProofByTransaction` to get epoch receipt proof.
- Add `include_eth_recepits` option (default to false) for `cfx_getEpochReceipts`.

## v2.2.4
- Update the `Log` data format returned by cfx filter RPCs.
- Implement `trace_epoch` in the core space RPC endpoint to return traces of two spaces in an epoch.

## v2.2.3
- Add debug RPCs `debug_getTransactionsByEpoch` and `debug_getTransactionsByBlock` to get the original transactions in both spaces atomically. This is only available in the local RPC port and phantom transactions will not be returned.

## v2.2.2

- A new scheme for epoch parameter like [EIP-1898](https://eips.ethereum.org/EIPS/eip-1898), which has 3 optional fields:
  - `epochNumber`. Corresponding to `blockNumber`
  - `blockHash`. Same as EIP-1898 `blockHash`
  - `requirePivot`. Corresponding to `requireCanonical`. And according to previous behaviour (including espace `eth_call` and core space `EpochReceipt`), this value will default to `true`
- Add filter RPCs in core space including `cfx_newFilter`, `cfx_newBlockFilter`, `cfx_newPendingTransactionFilter`, `cfx_getFilterChanges`, `cfx_getFilterLogs`, `cfx_uninstallFilter`
- Add a new RPC `pos_getAccountByPowAddress` to get pos account from pow address

## v2.2.1

- Fix `pending` tag behaviour in espace. Now `pending` tag will be considered as `latest` tag except for `eth_getTransactionCount`.
- Fix `cfx_getDepositList` and `cfx_getVoteList` return value format.

## v2.2.0

- Support `safe` and `finalized` block tag in espace.
  - `safe` block number corresponds to `latest_confirmed` and `finalized` corresponds to `latest_finalized`

## v2.1.1

- Add filter RPCs in eSpace including `eth_newFilter`, `eth_newBlockFilter`, `eth_newPendingTransactionFilter`, `eth_getFilterLogs`, `eth_getFilterChanges`, `eth_uninstallFilter`

## v2.1.0

- Support `eth_subscribe` and `eth_unsubscribe` in eSpace RPCs.
- Add an RPC method [`cfx_getParamsFromVote`](https://developer.confluxnetwork.org/conflux-doc/docs/json_rpc#cfx_getparamsfromvote) to return the currently used value of the voted parameters.
- Return null for getting skipped transactions and receipts. Whether they will be returned was nondeterministic before, but now they are ensured to be null.
- When querying logs, use LatestState instead of the to epoch number when the to epoch number is greater than LatestState

## v2.0.3

- `cfx_getLogs` and `eth_getLogs` will no longer support the parameters limit and offset. They are not efficient and can be replaced by setting the block/epoch range instead.
- `cfx_clientVersion` will have included more information like `web3_clientVersion` in eSpace.
- `fromEpoch` will default to "latest_state" in `cfx_getLogs`.
- `fromBlock` will default to "latest" in `eth_getLogs`.

## v2.0.2

### eSpace

- Add a new RPC `eth_getAccountPendingTransactions` to get pending transactions by address, also return the first pending transaction's pending reason
- Support WebSockets for eth APIs
- Support block hash param for `eth_call` (EIP1898)
- `eth_call`, `eth_estimate` will respect `from`'s balance if passed, if balance is not enough will return error. If from is not passed then use a random one, which balance will be very big.
- `eth_sendRawTransaction` will reject transaction if sender's balance is not enough, return error like `Transaction {:?} is discarded due to out of balance, needs {:?} but account balance is {:?}`
- If `eth_call`, `eth_estimate` method call raise error, and the `error.data` is string, it will directly return. In version before v2.0.2 they are hex encoded, is not convenient.

### Core Space

- `cfx_call`, `cfx_estimateGasAndCollateral` will respect `from`'s balance if passed, if balance is not enough will return error. If from is not passed then use a random one, which balance will be very big.
- `cfx_sendRawTransaction` will reject transaction if sender's balance is not enough, return error like `Transaction {:?} is discarded due to out of balance, needs {:?} but account balance is {:?}`
- If `cfx_call`, `cfx_estimateGasAndCollateral` method call raise error, and the `error.data` is string, it will directly return. In version before v2.0.2 they are hex encoded, is not convenient.

## v2.0.1

- Report error in `cfx_getLogs` and `eth_getLogs` if `get_logs_filter_max_limit` is configured but the query would return more logs. The previous behavior of `cfx_getLogs` was to silently truncate the result. The previous behavior of `eth_getLogs` was to raise an error when `filter.limit` is too low, regardless of how many logs the query would result in.
- `eth_gasPrice` now estimate gas prices accurately instead of returning a fixed value.
- Support phantom transactions and return correct fields in eSpace `trace` RPCs.
- Add fields `valid` and `createType` for eSpace `trace` RPCs.
- Add RPC `rpc_methods` to return all available methods and `rpc_modules` to return all RPC modules.
- Add `totalEspaceTokens` in the response of `cfx_getSupplyInfo`.
- Add local RPCs `pos_start_voting`, `pos_stop_voting`, and `pos_voting_status`. Check #2438 for details.