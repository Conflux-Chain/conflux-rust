# 1.0.0

## Bug Fixes

- Fix bug where users need to restart node before they can use a newly created account to send transactions.

## Enhancements

- Use updated hash types in account store. Some of the hex string in the json
file have and require "0x" prefix in the new format.

## Incompatible changes

- CIP-8 Move all the collateral settlement to the end of execution.
