# 1.0.0

## Bug Fixes

- Fix bug where users need to restart node before they can use a newly created account to send transactions.
- Fix code() return value for uninitialized contract.
- Fix bug in kill_account after which the contract account is revived by simple transaction.
- Fix the place of collateral refund for suicide contracts.
- Fix missing StorageKey conversion from bytes of DepositList and VoteList.

## Incompatible changes

- CIP-5 Fix corner case in MPT key encoding.
- CIP-8 Move all the collateral settlement to the end of execution.
- CIP-10 Base mining reward finalization.
- CIP-12 Allow non-zero collateral contract to be killed.
- CIP-13 Use Big-Endian MPT Keys.
