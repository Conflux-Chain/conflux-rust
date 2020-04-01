# 0.3.0

## Blockchain Core Updates (Not Backward Compatible)

1. Change the address scheme of Conflux. All normal address now start with 0x1.
All smart contracts address now start with 0x8. Note that your private key will
still work as long as you replace the first character in your hex address with
``0x1``. For example, if your address is 0x7b5c..., after this update your
address will change to 0x1b5c...

You need to use new SDK tools to connect with the main chain, otherwise your
transaction will be rejected as invalid. 

## RPC/CLI Updates

1. Change the CLI interface subcommand from `debug` to `local`. Its
functionality remains the same.

## Bug Fixes

## Improvements

1. Make the consensus layer to prioritize meaning blocks first. It will improve
the overall performance in facing of DoS attacks. It will also prioritize
self-mined blocks as a desirable effect.
