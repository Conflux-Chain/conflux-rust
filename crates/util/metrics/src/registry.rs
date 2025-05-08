// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::metrics::Metric;
use lazy_static::lazy_static;
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};

lazy_static! {
    pub static ref DEFAULT_REGISTRY: RwLock<Registry> =
        RwLock::new(Registry::default());
    pub static ref DEFAULT_GROUPING_REGISTRY: RwLock<GroupingRegistry> =
        RwLock::new(GroupingRegistry::default());
}

#[derive(Default)]
pub struct Registry {
    metrics: HashMap<String, Arc<dyn Metric>>,
}

impl Registry {
    pub fn register(&mut self, name: String, metric: Arc<dyn Metric>) {
        assert!(!self.metrics.contains_key(&name));
        self.metrics.insert(name, metric);
    }

    pub fn get_all(&self) -> &HashMap<String, Arc<dyn Metric>> { &self.metrics }

    pub fn clear(&mut self) { self.metrics.clear(); }
}

#[derive(Default)]
pub struct GroupingRegistry {
    groups: HashMap<String, HashMap<String, Arc<dyn Metric>>>,
}

impl GroupingRegistry {
    pub fn register(
        &mut self, group_name: String, metric_name: String,
        metric: Arc<dyn Metric>,
    ) {
        let group_entry =
            self.groups.entry(group_name).or_insert_with(HashMap::new);
        assert!(
            !group_entry.contains_key(&metric_name),
            "Metric name {:?} already exists in the group ",
            &metric_name
        );
        group_entry.insert(metric_name, metric);
    }

    pub fn get_all(
        &self,
    ) -> &HashMap<String, HashMap<String, Arc<dyn Metric>>> {
        &self.groups
    }

    pub fn clear(&mut self) { self.groups.clear(); }
}
