use super::{
    call_tracer::CallTracer, checkpoint_tracer::CheckpointTracer,
    internal_transfer_tracer::InternalTransferTracer,
    opcode_tracer::OpcodeTracer, StorageTracer,
};

pub trait TracerTrait:
    CheckpointTracer
    + CallTracer
    + InternalTransferTracer
    + OpcodeTracer
    + StorageTracer
{
}

impl<
        T: CheckpointTracer
            + CallTracer
            + InternalTransferTracer
            + OpcodeTracer
            + StorageTracer,
    > TracerTrait for T
{
}
