use super::{
    CallTracer, CheckpointTracer, InternalTransferTracer, OpcodeTracer,
    SetAuthTracer, StorageTracer,
};

pub trait TracerTrait:
    CheckpointTracer
    + CallTracer
    + InternalTransferTracer
    + StorageTracer
    + OpcodeTracer
    + SetAuthTracer
{
}

impl<
        T: CheckpointTracer
            + CallTracer
            + InternalTransferTracer
            + OpcodeTracer
            + StorageTracer
            + SetAuthTracer,
    > TracerTrait for T
{
}
