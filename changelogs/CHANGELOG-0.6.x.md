# 0.6.3

## Improvements

- Block info returned by rpc methods `cfx_getBlockByEpochNumber`, `cfx_getBlockByHash`, `cfx_getBlockByHashWithPivotAssumption` add one new field `gasUsed` (backward compatible)

- Revise `cfx_getStorageRoot` output. Now it always returns a JSON objects with three fields `"delta"`, `"intermediate"`, and `"snapshot"`. These fields are either `null`, `"TOMBSTONE"`, or a hash string (e.g. `"0x0240a5a3486ac1cee71db22b8e12f1bb6ac9f207ecd81b06031c407663c20a94"`).

# 0.6.2

## Improvement
- Start stratum services automatically if `mining_author` is set. 
Use `mining_type` to allow start CPU mining or disable mining manually.
- Add rpc method `tx_inspect_pending` to help developer get their pending info.
- Debug rpc `txpool_inspect` `txpool_content` `getTransactionsFromPool` add an optional parameter `address` to enable filter by account  

# 0.6.0

## Bug Fixes

- Fix inconsistent logics for TrackTouched.

- Make sure all internal account exists at genesis block, otherwise some
readonly operation may crash.

- Fix incorrect usages of require() in vm operations. In most cases creation of
basic account in its absense is undesired, especially when the address is a
contract. When a user account is to be created, the address space is checked.

- Fix issue in processing snapshot chunk boundary which caused crash. The bug
was caused by a wrong assumption of the uniqueness of the trie proof key.

- Fix incorrect receipt in refunding code collateral when contract suicides.

- Fix crash when a contract suicides during creation.

- Fix db error handling for EVM create / call.

- Prevent crashes due to unchecked address space.

## Incompatible Changes

- Change StorageValue serialization to reduce space.

- Changed COMMISSION_PRIVILEGE_STORAGE_VALUE.

- Remove address from Account rlp format, which was included unexpectedly
before.

- Changed RewardInfo struct to add author info.

- Invalid address in transaction execution will trigger an error. 

- The SELFDECONSTRUCT operation will fail if refund to invalid address.

- Change the logic when reentrancy happens. (Message call with empty data and <= 2300 gas is exempt from reentrancy check.)


## Improvements

- Unify all public rpc with hex number, the following fields from RPC will be changed from decimal to hexadecimal:
    - BlameInfo.blame
    - Block.blame
    - CallRequest.storageLimit
    - ConsensusGraphBlockState.blockStatus
    - EpochNumber::Num
    - Receipt.index
    - Receipt.epochNumber
    - Receipt.outcomeStatus
    - Status.pendingTxNumber
    - SyncGraphBlockState.timestamp

- Rename local rpc send_transaction with cfx_sendTransaction.

- Improve the performance of the consensus layer for unstable TreeGraph scenarios. 

- Complete the protocol version mechanism for node communications and bump
the protocol version to V2. The change is backwards-compatible except for
msgid::THROTTLE (0xfe).

- Add chain_id field into sync protocol and light protocol handshake message
so that peers can disconnect peers from another Conflux chain, e.g. testnet,
another testnet.

- Keep network_id the same as chain_id. Setting network_id is only for local
experimental purposes.

- Improve the transaction replacement rule in tx-pool: now a transaction can
replace one with same sender and nonce by higher gas-price or by same gas-price
and larger epoch height.

- Change the nonce to 256 bits from 64 bits

- Introduce nonce based lower bound in the PoW difficulty calculation. This
will help to defend against block withholding attack among mining pools in
future. With this change and careful PoW design, a mining pool can withhold 
the top 128 bits of the nonce as the server nonce and the participants of 
the pool will not be able to tell whether they mined a block or not.

- Improve the stratum protocol to make it more consistent with the convention.
Now the stratum protocol can correctly work with an external miner.

- Separate `deposit_list` and `vote_stake_list` from `Account` and adjust the gas cost for `withdraw`, `deposit`, `vote_lock` internal contract call. Now, the gas cost for there three functions is related with the length of `deposit_list` or `vote_stake_list`.

- Disable transaction index persistence by default. This will reduce the disk usage 
for miners. If you want to reliably serve transaction-related RPCs, you should 
set `persist_tx_index=true` in the configuration file manually.

- A new RPC ctx_getBlockRewardInfo to query block reward information inside a 
given epoch.

- Compute transaction root and receipts root by a simple MPT where the key is
the index in big endian bytes representation of fixed length with leading zero
and the value is the bytes representation of the corresponding data, e.g.
transaction hash for transaction root, Receipt rlp for block receipts root.
The receipts root is the Merkle root of the simple MPT of block receipts roots.

- Use raw bytes in blame vec hash calculation instead of rlp because each 
element of the vec is fixed length H256.

- Add support for CHAINID, SELFBALANCE, BEGINSUB, JUMPSUB, RETURNSUB opcodes.

- NUMBER opcode in call_virtual() now returns the correct block number.

- BLOCKHASH opcode now returns the last block hash (i.e., ``blockhash(block.number - 1)``) 
or zero if not querying the last block hash.

- Disable reentrancy of contract calling through other contracts. 

- Change the default value of `from_epoch` in RPC `cfx_getLogs` from "earliest" to "latest_checkpoint".
Now if no `from_epoch` is specified, it will only return logs after the latest checkpoint.

- Improve archive and full node log filtering. Change `filter.to_epoch` default to `"latest_state"`. Limit `filter.block_hashes` to up to 128 items.

- Change internal contracts address to 0x088800...

- Enable overflow-checks for release build, to make sure that underflow is
impossible.

- Reduce the lock dependency between the transaction pool and the consensus engine to improve the performance.

- Transaction pool will not start until the node finishes the catch-up. This
avoids inconsistent transaction pool issues during the catch up.

- New cfx_clientVersion() rpc call to return a string with versions

- Change CREATE/CREATE2 maximum code size from 24K to 48K


