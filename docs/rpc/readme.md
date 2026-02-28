# eSpace RPC Documentation

## eth_getBlockByNumber pending tag

When the `eth_getBlockByNumber` method is called with the `pending` tag, the eSpace RPC node returns the current latest mined blocks. These blocks have already been included in the blockchain but have not yet been executed (due to a 5-epoch delay). For further details, please refer to [Conflux's Block Deferred Execution Mechanism.](https://doc.confluxnetwork.org/docs/core/core-space-basics/transactions/lifecycle#4-deferring-5-epochs---executed)