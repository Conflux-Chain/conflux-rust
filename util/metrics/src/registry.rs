use crate::metrics::Metric;
use lazy_static::lazy_static;
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};

lazy_static! {
    pub static ref DEFAULT_REGISTRY: RwLock<Registry> =
        RwLock::new(Registry::default());
}

#[derive(Default)]
pub struct Registry {
    metrics: HashMap<String, Arc<Metric>>,
}

impl Registry {
    pub fn register(&mut self, name: String, metric: Arc<Metric>) {
        assert!(!self.metrics.contains_key(&name));
        self.metrics.insert(name, metric);
    }

    pub fn get_all(&self) -> &HashMap<String, Arc<Metric>> { &self.metrics }
}
