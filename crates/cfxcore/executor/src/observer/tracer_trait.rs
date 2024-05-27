use super::{
    CallTracer, CheckpointTracer, InternalTransferTracer, OpcodeTracer,
    StorageTracer,
};

pub trait TracerTrait:
    CheckpointTracer
    + CallTracer
    + InternalTransferTracer
    + StorageTracer
    + OpcodeTracer
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
