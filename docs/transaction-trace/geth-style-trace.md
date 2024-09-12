# Geth Style Trace

Ethereum geth client provides [a way to trace transactions](https://geth.ethereum.org/docs/developers/evm-tracing). The trace is useful for debugging and understanding the transaction execution. Geth's trace related RPC methods are under [`debug`](https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-debug#debugtracetransaction) namespace, include:

- `debug_traceTransaction`
- `debug_traceBlock`
- `debug_traceBlockByNumber`
- `debug_traceBlockByHash`
- `debug_traceCall`

Geth support different kind of traces, include:

- opcode
- prestateTracer
- 4byteTracer
- noopTracer
- callTracer

And serveral builtin JS tracers, include:

- bigram
- evmdis
- unigram
- opcount
- trigram
- unigram

Geth also support writing custom tracer in [Go and Js](https://geth.ethereum.org/docs/developers/evm-tracing/custom-tracer).

debug_traceCall method suport [state override](https://geth.ethereum.org/docs/developers/evm-tracing/built-in-tracers#state-overrides).

## Conflux Implementation

Conflux eSpace has implemented main features of geth style trace, include:

- `debug_traceTransaction`
- `debug_traceBlockByNumber`
- `debug_traceBlockByHash`
- `debug_traceCall`

Currently supported tracers:

- opcode
- prestateTracer (Working)
- 4byteTracer
- noopTracer
- callTracer

We will support writing custom tracer with Js in the future.

To use eSpace trace RPC methods, you need to enable `ethdebug` API module in the config file.

```toml
public_evm_rpc_apis = "eth,ethdebug"
```

### Opcode Tracer

Currently the opcode trace's structLogs `error` field is not implemented.

Conflux does not have refund mechanism, so the `refund` field is omitted.

### state override

Currently we do not support state override in `debug_traceCall` method.

## FAQs

1. Does trace RPC methods support eSpace PhantomTransaction traces?
    
    Currently, no. We will support it in the future.

## Resources

1. [Geth EVM Tracing](https://geth.ethereum.org/docs/developers/evm-tracing)
2. [Geth Debug RPC](https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-debug)
3. [Geth Custom Tracer](https://geth.ethereum.org/docs/developers/evm-tracing/custom-tracer)
4. [Geth State Override](https://geth.ethereum.org/docs/developers/evm-tracing/built-in-tracers#state-overrides)
5. [Geth Tracer](https://geth.ethereum.org/docs/developers/evm-tracing/built-in-tracers)
6. [Paradigmxyz's ultimate_evm_tracing_reference](https://github.com/paradigmxyz/ultimate_evm_tracing_reference)