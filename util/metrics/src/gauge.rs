use crate::{
    metrics::{is_enabled, Metric, ORDER},
    registry::{DEFAULT_GROUPING_REGISTRY, DEFAULT_REGISTRY},
};
use std::sync::{atomic::AtomicUsize, Arc};

pub trait Gauge<T: Default>: Send + Sync {
    fn value(&self) -> T { T::default() }
    fn update(&self, _value: T) {}
}

struct NoopGauge;
impl<T: Default> Gauge<T> for NoopGauge {}

#[macro_export]
macro_rules! construct_gauge {
    ($name:ident, $value_type:ty, $data_type:ty) => {
        #[derive(Default)]
        pub struct $name {
            value: $value_type,
        }

        impl $name {
            pub fn register(name: &str) -> Arc<dyn Gauge<$data_type>> {
                if !is_enabled() {
                    return Arc::new(NoopGauge);
                }

                let gauge = Arc::new($name::default());
                DEFAULT_REGISTRY
                    .write()
                    .register(name.into(), gauge.clone());

                gauge
            }

            pub fn register_with_group(
                group: &str, name: &str,
            ) -> Arc<dyn Gauge<$data_type>> {
                if !is_enabled() {
                    return Arc::new(NoopGauge);
                }

                let gauge = Arc::new($name::default());
                DEFAULT_GROUPING_REGISTRY.write().register(
                    group.into(),
                    name.into(),
                    gauge.clone(),
                );

                gauge
            }
        }

        impl Gauge<$data_type> for $name {
            fn value(&self) -> usize { self.value.load(ORDER) }

            fn update(&self, value: usize) { self.value.store(value, ORDER); }
        }

        impl Metric for $name {
            fn get_type(&self) -> &str { "Gauge" }
        }
    };
}

construct_gauge!(GaugeUsize, AtomicUsize, usize);
