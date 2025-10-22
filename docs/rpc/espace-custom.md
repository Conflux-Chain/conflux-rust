# eSpace Custom RPC endpoints

Some RPC endpoints unique to Conflux eSpace.

## debug

### debug_blockProperties

The structure of Conflux's blockchain is based on DAG, and an Epoch usually consists of multiple blocks. Transaction execution is performed epoch by epoch. In eSpace, an eSpace block actually corresponds to an Epoch in the DAG, which means it contains transactions from multiple blocks in the DAG.

Due to this feature, transactions within a single Conflux eSpace block may have different block contexts (coinbase, timestamp, difficulty) during execution. Currently, the block properties affected by this issue include:

1. coinbase
2. difficulty/prevrandao
3. gaslimit: current block gaslimit
4. timestamp
5. basefee

Conflux eSpace does not support blobhash and blobbasefee because Conflux does not support EIP-4844. These two opcodes will return default values during execution.

Some services require verification of transaction execution, so we provide the `debug_blockProperties` interface to query the block properties of all transactions in an eSpace block.

```json
{
  "jsonrpc": "2.0",
  "method": "debug_blockProperties",
  "params": ["0x1B4"], // block number or hash
  "id": 1
}

{
    "jsonrpc": "2.0",
    "id": 1,
    "result": [
        {
            "txHash": "0x3719bb0b4385a7e0266d1e266166d821b351a38a1a78f2e36df99c73bbbc15ae",
            // the DAG block hash where this transaction is included
            "innerBlockHash": "0x446012a81945dc9cde4eca03697e43d5f80beed878d78b9829b54cb9a1f9f7a4",
            "coinbase": "0x1d69d968e3673e188b2d2d42b6a385686186258f",
            "difficulty": "0x4",
            "gasLimit": "0x3938700",
            "timestamp": "0x68ee1848",
            "baseFeePerGas": "0x1"
        }
    ]
}
```
