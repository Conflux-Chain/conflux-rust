# Parity Trace Style

Both Conflux Core Space and eSpace support parity style trace RPC methods, but with some differences.

## Core Space

Check [this doc](https://doc.confluxnetwork.org/docs/core/build/json-rpc/trace_rpc) for Core Space methods.

## eSpace

eSpace methods are compatible with [parity](https://openethereum.github.io/JSONRPC-trace-module) and [erigon](https://docs.erigon.tech/advanced/JSONRPC-trace-module) style trace RPC methods. The following table lists the supported methods:

| Method Name | Supported |
| ----------- | ----------- |
| `trace_block` | ✅ |
| `trace_filter` | ✅ |
| `trace_get` | ✅ |
| `trace_transaction` | ✅ |
| `trace_call` |  |
| `trace_callMany` |  |
| `trace_rawTransaction` |  |
| `trace_replayTransaction` |  |
| `trace_replayBlockTransactions` |  |
| `trace_blockSetAuth` | Conflux-specific method | 

Currently, trace data only supports Call and Create types. Since Conflux’s block rewards and PoS rewards occur in Core Space, there will be no Reward type trace data in eSpace.

### Trace SetAuth(7702)

eSpace has added a new method called trace_blockSetAuth, which is used to retrieve the trace data for SetAuth operations in EIP-7702 transactions. The returned result is as follows:

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": [
        {
            "action": {
                "address": "0xf0109fc8df283027b6285cc889f5aa624eac1f55",
                "chainId": "0x401",
                "nonce": "0x1",
                "author": "0x3d69d968e3673e188b2d2d42b6a385686186258f"
            },
            "result": "invalid_nonce",
            "transactionPosition": 0,
            "transactionHash": "0x716f6f3294346099d98d5f9b0e12846647e1d17b9076d1a5ac0e42dac72f7229",
            "blockNumber": 7800,
            "blockHash": "0x015880a004ff96fed4161353994958d0f09eeae770f73ca888f105dc9f4ef1cc"
        }
    ]
}
```

`action` The author field is recovered from the Authorization. If the signature is invalid, this field will be empty.

`result` This field indicates the execution result of the setAuth operation. Possible values include:

- `success`: Set Auth success
- `invalid_chain_id`: Chain ID is not equal to the current chain ID also not equal to 0
- `invalid_nonce`: Nonce is not equal to the current nonce
- `nonce_overflow`: Nonce is overflow
- `invalid_signature`: Signature is invalid
- `account_can_not_set_auth`: Only account is empty or already delegated can set auth
