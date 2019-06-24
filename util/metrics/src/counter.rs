use crate::{
    metrics::{is_enabled, Metric, ORDER},
    registry::DEFAULT_REGISTRY,
};
use std::sync::{atomic::AtomicUsize, Arc};

pub trait Counter<T: Default>: Send + Sync {
    fn count(&self) -> T { T::default() }
    fn dec(&self, _delta: T) {}
    fn inc(&self, _delta: T) {}
}

struct NoopCounter;
impl<T: Default> Counter<T> for NoopCounter {}

#[macro_export]
macro_rules! construct_counter {
    ($name:ident, $value_type:ty, $data_type:ty) => {
        #[derive(Default)]
        pub struct $name {
            value: $value_type,
        }

        impl $name {
            pub fn register(name: &'static str) -> Arc<Counter<$data_type>> {
                if !is_enabled() {
                    return Arc::new(NoopCounter);
                }

                let counter = Arc::new($name::default());
                DEFAULT_REGISTRY
                    .write()
                    .register(name.into(), counter.clone());

                counter
            }
        }

        impl Counter<$data_type> for $name {
            fn count(&self) -> $data_type { self.value.load(ORDER) }

            fn dec(&self, delta: $data_type) {
                self.value.fetch_sub(delta, ORDER);
            }

            fn inc(&self, delta: $data_type) {
                self.value.fetch_add(delta, ORDER);
            }
        }

        impl Metric for $name {
            fn get_type(&self) -> &'static str { stringify!($name) }
        }
    };
}

construct_counter!(CounterUsize, AtomicUsize, usize);
