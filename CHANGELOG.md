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

You need to use new SDK tools to connect with the main chain, otherwise your
transaction will be rejected as invalid. 

## RPC/CLI Updates

- Change the CLI interface subcommand from `debug` to `local`. Its
functionality remains the same.

## Bug Fixes

## Improvements

- Make the consensus layer to prioritize meaning blocks first. It will improve
the overall performance in facing of DoS attacks. It will also prioritize
self-mined blocks as a desirable effect.

