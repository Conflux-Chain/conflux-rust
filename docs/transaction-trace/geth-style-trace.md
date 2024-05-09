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


