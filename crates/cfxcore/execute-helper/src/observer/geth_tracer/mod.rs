use cfx_executor::observer::{
    CallTracer, CheckpointTracer, DrainTrace, InternalTransferTracer,
    OpcodeTracer, StorageTracer,
};

pub struct GethTracer {
    // TODO[geth-tracer]: Fill data here
}

impl DrainTrace for GethTracer {
    fn drain_trace(self, map: &mut typemap::ShareDebugMap) {
        // TODO[geth-tracer]: Compute output for one transaction here.
        map.insert::<GethTracerKey>(());
    }
}

pub struct GethTracerKey;

impl typemap::Key for GethTracerKey {
    // TODO[geth-tracer]: Define your output type here
    type Value = ();
}

impl CheckpointTracer for GethTracer {
    // TODO[geth-tracer]: Implement hook handler in needed.
}

impl CallTracer for GethTracer {}

impl InternalTransferTracer for GethTracer {}

impl StorageTracer for GethTracer {}

impl OpcodeTracer for GethTracer {
    fn do_trace_opcode(&self, enabled: &mut bool) {
        *enabled |= true;
        // TODO[geth-tracer]: Tell the executor if trace_opcode is enabled.
    }
}
