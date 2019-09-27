// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    metrics::is_enabled, register_meter_with_group, Counter, CounterUsize,
    Meter,
};
use std::sync::Arc;

pub trait Queue: Send + Sync {
    fn enqueue(&self, _n: usize) {}
    fn dequeue(&self, _n: usize) {}
}

fn register_queue_with_name(
    group_name: &str, enq_name: &str, deq_name: &str, queued_name: &str,
) -> Arc<dyn Queue> {
    if !is_enabled() {
        return Arc::new(Noop);
    }

    Arc::new(Standard {
        enqueue_tps: register_meter_with_group(group_name, enq_name),
        dequeue_tps: register_meter_with_group(group_name, deq_name),
        queued: CounterUsize::register_with_group(group_name, queued_name),
    })
}

pub fn register_queue(name: &str) -> Arc<dyn Queue> {
    register_queue_with_name(name, "enq_tps", "deq_tps", "queued")
}

pub fn register_queue_with_group(group: &str, name: &str) -> Arc<dyn Queue> {
    register_queue_with_name(
        group,
        format!("{}_enq_tps", name).as_str(),
        format!("{}_deq_tps", name).as_str(),
        format!("{}_queued", name).as_str(),
    )
}

struct Noop;
impl Queue for Noop {}

struct Standard {
    enqueue_tps: Arc<dyn Meter>,
    dequeue_tps: Arc<dyn Meter>,
    queued: Arc<dyn Counter<usize>>,
}

impl Queue for Standard {
    fn enqueue(&self, n: usize) {
        self.enqueue_tps.mark(n);
        self.queued.inc(n);
    }

    fn dequeue(&self, n: usize) {
        self.dequeue_tps.mark(n);
        self.queued.dec(n);
    }
}
