# 0.4.0

## Bug Fixes

- Fix a potential crash bug in the transaction pool compoenent

- Stop marking OverlayAccount dirty on read access. This will influnce the state root. 

- Add missing transaction verifications for invalid block.

- Fill in correct block gas limit value for mining.

## Improvements

- Improve the transaction address check at RPC

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
