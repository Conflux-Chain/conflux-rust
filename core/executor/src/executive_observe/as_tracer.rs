use super::tracer_trait::TracerTrait;

pub trait AsTracer {
    fn as_tracer<'a>(&'a mut self) -> Box<dyn 'a + TracerTrait>;
}

impl AsTracer for () {
    fn as_tracer<'a>(&'a mut self) -> Box<dyn 'a + TracerTrait> {
        Box::new(self)
    }
}
