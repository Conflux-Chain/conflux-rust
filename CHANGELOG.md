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

## Improvements

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

# 0.5.0

## Improvements

- Add fields in Receipt: gas_fee, gas_sponsored, storage_sponsored. Accumulate gas_used in Receipt, not gas_charged.

- Delay block requests when we cannot process them to avoid wasting network bandwidth.

- Set block gas limit for Genesis block to 30_000_000.

- Define gas_used to be transaction gas limit for NotEnoughCash, the same as all other exceptions.

- Add support for WebSockets in RPC.

- cfx_gasPrice will return a price with at least 1000000000, i.e. 1GDrip.

- Move getstatus RPC from test to common, and renamed with cfx_getStatus.

## Bug Fixes

- Fix UnexpectedResponse from honest peers that causes peer demotion.

- Remove some untrue debug assert.

- Forbidden CALLCODE and DELEGATECALL to internal contracts.

- RPC now returns the correct rlp size of the block

- Fix a race condition that may cause optimistic execution to panic.

- Fill in correct block gas limit value for mining.

- Fix definitions and logics in transaction early execution error checking.

- Use block_count - 1 in target difficulty calculation because it's the unbiased estimation of exponential distribution parameter (past mining power).

## Improvements

- Add cfx_getConfirmationRiskByHash RPC to get confirmation risk by block hash.

- Add getTransactionsFromPool debug RPC to collect transactions in pool.

# 0.4.0

## Bug Fixes

- Fix a potential crash bug in the transaction pool compoenent

- Stop marking OverlayAccount dirty on read access. This will influnce the state root. 

- Do not mark OverlayAccount dirty in sub_balance 0 for non-existence account.

- Add missing transaction verifications for invalid block.

## Improvements

- Improve the transaction address check at RPC

- Change the test net PoW to use double keccak

## EVM Updates

- Decide the storage owner (who is responsible for storage collateral) at the beginning of the transaction. 

- Only check the storage limit and balance for storage collateral at the end of EVM execution. 

# 0.3.2

## Bug Fixes

- Fix an issue that GetBlockHashesByEpoch containing blocks before checkpoint may cause the node to crash.

- Quick fix for possible duplicate block inserted into the consensus worker thread.

# 0.3.0

## Blockchain Core Updates (Not Backward Compatible)

- Changes the address scheme of Conflux. All normal address now start with 0x1.
All smart contracts address now start with 0x8. Note that your private key will
still work as long as you replace the first character in your hex address with
``0x1``. For example, if your address is 0x7b5c..., after this update your
address will change to 0x1b5c...

- Changes the state Merkle root calculation method. Merkle is calculated based
on constructed raw keccak input byte string instead of serialized rlp; checks if
compressed_path starts on the second nibble of a byte; makes sure that with the
constructed keccak input string adversary cannot construct a compressed path to
create a path Merkle of the same value as a node Merkle.

- Each epoch now has a limit of executing 200 blocks. If there are more than
200 blocks in an epoch. Only the last 200 blocks will be executed. This change
is designed to battle DoS attacks about hiding and generating a lot of blocks
suddenly.

- Add storage_root support in Conflux MPT. Define storage root as the Merkle
root computed on the account's storage subtree root node, ignoring the
compressed path; 2) force the storage root node to existing by setting a
StorageLayout value at the storage node. 

You need to use new SDK tools to connect with the main chain, otherwise your
transaction will be rejected as invalid. 

## EVM Updates

- Change the gas used in SSTORE operation to 5000 gas, no matter the zero-ness
is changed or not. And we no longer refund gas in releasing storage entry. 

## RPC/CLI Updates

- Change the CLI interface subcommand from `debug` to `local`. Its
functionality remains the same.

- Add a RPC cfx_getSkippedBlocksByEpoch to query skipped blocks of an epoch

- Add a corresponding CLI interface to query skipped blocks via local RPC

- Refactor RPC interface now most RPC takes HEX parameters and returns HEX

## Bug Fixes

- Fix an issue that may cause the P2P layer to not propagate out-of-era blocks properly

- Fix an issue that Conflux RPC may return incorrect estimate.

- Fix an issue that virtual call RPC may fail if the caller does not have enough balance

- Fix an issue that failing to send a pending request can make a block not received.

- Fix an issue that not-graph-ready compact blocks are not fully received.


## Improvements

- Make the consensus layer to prioritize meaningful blocks first. It will
improve the overall performance in facing of DoS attacks. It will also
prioritize self-mined blocks as a desirable effect.
