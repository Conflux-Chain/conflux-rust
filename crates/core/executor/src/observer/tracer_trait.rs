use super::{
    call_tracer::CallTracer, checkpoint_tracer::CheckpointTracer,
    internal_transfer_tracer::InternalTransferTracer,
};

pub trait TracerTrait:
    CheckpointTracer + CallTracer + InternalTransferTracer
{
}

impl<T: CheckpointTracer + CallTracer + InternalTransferTracer> TracerTrait
    for T
{
}
