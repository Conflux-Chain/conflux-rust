// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    metrics::{is_enabled, Metric, ORDER},
    registry::{DEFAULT_GROUPING_REGISTRY, DEFAULT_REGISTRY},
};
use std::sync::{atomic::AtomicUsize, Arc};

pub trait Counter<T: Default>: Send + Sync {
    fn count(&self) -> T {
        T::default()
    }
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
            pub fn register(name: &str) -> Arc<dyn Counter<$data_type>> {
                if !is_enabled() {
                    return Arc::new(NoopCounter);
                }

                let counter = Arc::new($name::default());
                DEFAULT_REGISTRY
                    .write()
                    .register(name.into(), counter.clone());

                counter
            }

            pub fn register_with_group(
                group: &str, name: &str,
            ) -> Arc<dyn Counter<$data_type>> {
                if !is_enabled() {
                    return Arc::new(NoopCounter);
                }

                let counter = Arc::new($name::default());
                DEFAULT_GROUPING_REGISTRY.write().register(
                    group.into(),
                    name.into(),
                    counter.clone(),
                );

                counter
            }
        }

        impl Counter<$data_type> for $name {
            fn count(&self) -> $data_type {
                self.value.load(ORDER)
            }

            fn dec(&self, delta: $data_type) {
                self.value.fetch_sub(delta, ORDER);
            }

            fn inc(&self, delta: $data_type) {
                self.value.fetch_add(delta, ORDER);
            }
        }

        impl Metric for $name {
            fn get_type(&self) -> &str {
                "Counter"
            }
        }
    };
}

construct_counter!(CounterUsize, AtomicUsize, usize);
