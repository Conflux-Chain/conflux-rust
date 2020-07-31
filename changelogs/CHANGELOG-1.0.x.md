# 1.0.0

## Bug Fixes

- Fix bug where users need to restart node before they can use a newly created account to send transactions.
- Fix code() return value for uninitialized contract.
- Fix bug in kill_account after which the contract account is revived by simple transaction.
- Fix the place of collateral refund for suicided contracts.

## Incompatible changes

- CIP-8 Move all the collateral settlement to the end of execution.
