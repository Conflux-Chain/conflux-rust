# Advanced RPC

This document describes several advanced Conflux eSpace RPC interface implementations, primarily intended for debugging purposes.

## eth_simulateV1

The `eth_simulateV1` interface is used to simulate the execution of multiple blocks and transactions in a single batch. It is similar to `eth_call` but provides greater control over execution behavior and returns more detailed results.

For the specific interface specification, please refer to the Geth documentation: https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-eth#eth-simulate-v1

The core functionality of this method has been implemented, though some features are not yet supported, including:

1. The `validation` and `traceTransfers` parameters are currently ineffective.
2. Certain fields in `blockOverrides` are not yet supported: `number`, `random`, and `blockHash`.

Additionally, if fields for items in the calls array are omitted, they will mostly use default values. The `nonce` field will automatically increment based on the state at the specified block height.

When specifying a historical state height, the node must be a full-state node.