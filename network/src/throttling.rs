// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{Error, ErrorKind, ThrottlingReason};
use byte_unit::n_mb_bytes;
use lazy_static::lazy_static;
use metrics::{Gauge, GaugeUsize};
use parking_lot::RwLock;
use serde_derive::Serialize;
use std::sync::Arc;

lazy_static! {
    pub static ref THROTTLING_SERVICE: RwLock<Service> =
        RwLock::new(Service::new());
    static ref QUEUE_SIZE_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group(
            "network_system_data",
            "network_throttling_queue_size"
        );
    static ref HIGH_QUEUE_SIZE_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group(
            "network_system_data",
            "high_throttling_queue_size"
        );
    static ref LOW_QUEUE_SIZE_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group(
            "network_system_data",
            "low_throttling_queue_size"
        );
}

/// Throttling service is used to control the egress bandwidth, so as to avoid
/// too much egress data cached in buffer.
///
/// The throttling is achieved by monitoring the message send queue size of all
/// TCP sockets. Basically, the throttling is used in 2 ways:
///
/// 1. When the queue size reached the configured threshold, the synchronization
/// layer will reduce the number of peers to broadcast messages, e.g. new block
/// hashes, transaction digests.
///
/// 2. On the other hand, synchronization layer will also refuse to respond any
/// size sensitive message, e.g. blocks.
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// Maximum queue size.
    /// When reached, the queue will refuse any new data.
    queue_capacity: usize,
    /// Minimum queue size for throttling in manner of ratio.
    /// If queue size is less than `min_throttle_queue_size`, the throttling
    /// does not work. Once queue size exceeds the `min_throttle_queue_size`,
    /// the throttling begins to work in manner of linear ratio. Then, the
    /// synchronization layer will broadcast messages to less peers.
    min_throttle_queue_size: usize,
    /// Maximum queue size for throttling in manner of ratio.
    /// If queue size is between `min_throttle_queue_size` and
    /// `max_throttle_queue_size`, the throttling works in manner of linear
    /// ratio. Once queue size exceeds the `max_throttle_queue_size`, the
    /// throttling not only works in ratio manner, but also blocks any
    /// message size sensitive operations.
    max_throttle_queue_size: usize,
    /// Current queue size.
    cur_queue_size: usize,
    high_queue_size: usize,
    low_queue_size: usize,
}

impl Service {
    fn new() -> Service {
        Service {
            queue_capacity: n_mb_bytes!(256) as usize,
            min_throttle_queue_size: n_mb_bytes!(10) as usize,
            max_throttle_queue_size: n_mb_bytes!(64) as usize,
            cur_queue_size: 0,
            high_queue_size: 0,
            low_queue_size: 0,
        }
    }

    /// Initialize the throttling service.
    pub fn initialize(
        &mut self, cap_mb: usize, min_throttle_mb: usize,
        max_throttle_mb: usize,
    ) {
        // 0 < min_throttle_mb < max_throttle_mb < cap_mb
        assert!(cap_mb > max_throttle_mb);
        assert!(max_throttle_mb > min_throttle_mb);
        assert!(min_throttle_mb > 0);

        // capacity cannot overflow with usize type.
        let mb = n_mb_bytes!(1) as usize;
        assert!(std::usize::MAX / mb >= cap_mb);

        // ensure the current queue size will not exceed the capacity.
        let cap = cap_mb * mb;
        assert!(self.cur_queue_size <= cap);

        self.queue_capacity = cap;
        self.min_throttle_queue_size = min_throttle_mb * mb;
        self.max_throttle_queue_size = max_throttle_mb * mb;

        info!(
            "throttling.initialize: min = {}M, max = {}M, cap = {}M",
            min_throttle_mb, max_throttle_mb, cap_mb
        );
    }

    /// Mark data enqueued with specified `data_size`, and return the new queue
    /// size. If exceeds the queue capacity, return error with concrete reason.
    pub(crate) fn on_enqueue(
        &mut self, data_size: usize, is_high_priority: bool,
    ) -> Result<usize, Error> {
        if data_size > self.queue_capacity {
            debug!("throttling.on_enqueue: enqueue too large data, data size = {}, queue capacity = {}", data_size, self.queue_capacity);
            bail!(ErrorKind::Throttling(ThrottlingReason::QueueFull));
        }

        if self.cur_queue_size > self.queue_capacity - data_size {
            debug!("throttling.on_enqueue: queue size not enough, data size = {}, queue size = {}", data_size, self.cur_queue_size);
            bail!(ErrorKind::Throttling(ThrottlingReason::QueueFull));
        }

        self.cur_queue_size += data_size;
        if is_high_priority {
            self.high_queue_size += data_size
        } else {
            self.low_queue_size += data_size
        }
        trace!(
            "throttling.on_enqueue: queue size = {}",
            self.cur_queue_size
        );

        QUEUE_SIZE_GAUGE.update(self.cur_queue_size);
        HIGH_QUEUE_SIZE_GAUGE.update(self.high_queue_size);
        LOW_QUEUE_SIZE_GAUGE.update(self.low_queue_size);

        Ok(self.cur_queue_size)
    }

    /// Mark data dequeued with specified `data_size`, and return the updated
    /// queue size.
    pub(crate) fn on_dequeue(
        &mut self, data_size: usize, is_high_priority: bool,
    ) -> usize {
        if data_size > self.cur_queue_size {
            error!("throttling.on_dequeue: dequeue too much data, data size = {}, queue size = {}", data_size, self.cur_queue_size);
            self.cur_queue_size = 0;
            self.high_queue_size = 0;
            self.low_queue_size = 0;
        } else {
            self.cur_queue_size -= data_size;
            if is_high_priority {
                self.high_queue_size -= data_size
            } else {
                self.low_queue_size -= data_size
            }
        }

        trace!(
            "throttling.on_dequeue: queue size = {}",
            self.cur_queue_size
        );

        QUEUE_SIZE_GAUGE.update(self.cur_queue_size);
        HIGH_QUEUE_SIZE_GAUGE.update(self.high_queue_size);
        LOW_QUEUE_SIZE_GAUGE.update(self.low_queue_size);

        self.cur_queue_size
    }

    /// Validate the throttling queue size for any data size sensitive
    /// operations. If the queue size exceeds the `max_throttle_queue_size`,
    /// return error with concrete reason.
    pub fn check_throttling(&self) -> Result<(), Error> {
        if self.cur_queue_size > self.max_throttle_queue_size {
            debug!("throttling.check_throttling: throttled, queue size = {}, max throttling size = {}", self.cur_queue_size, self.max_throttle_queue_size);
            bail!(ErrorKind::Throttling(ThrottlingReason::Throttled));
        }

        Ok(())
    }

    /// Get the throttling ratio according to the current queue size.
    ///
    /// If the queue size is smaller than `min_throttle_queue_size`, return 1.0
    /// as throttling ratio. Then, it allows to broadcast messages to all peers.
    ///
    /// If the queue size is larger than `max_throttle_queue_size`, return 0 as
    /// throttling ratio. Then, it allows to broadcast messages to configured
    /// minimum peers.
    ///
    /// Otherwise, the throttling works in manner of linear ratio (0, 1), in
    /// which case it allows to broadcast messages to partial peers.
    pub fn get_throttling_ratio(&self) -> f64 {
        if self.cur_queue_size <= self.min_throttle_queue_size {
            return 1.0;
        }

        if self.cur_queue_size >= self.max_throttle_queue_size {
            debug!("throttling.get_throttling_ratio: fully throttled, queue size = {}, max throttling size = {}", self.cur_queue_size, self.max_throttle_queue_size);
            return 0.0;
        }

        let ratio = (self.max_throttle_queue_size - self.cur_queue_size) as f64
            / (self.max_throttle_queue_size - self.min_throttle_queue_size)
                as f64;

        debug!("throttling.get_throttling_ratio: partially throttled, queue size = {}, throttling ratio = {}", self.cur_queue_size, ratio);

        ratio
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_enqueue() {
        let mut service = super::Service::new();
        assert_eq!(service.on_enqueue(10, false).unwrap(), 10);
        assert_eq!(service.on_enqueue(20, false).unwrap(), 30);

        // enqueue data size is 0.
        assert_eq!(service.on_enqueue(0, false).unwrap(), 30);
    }

    #[test]
    fn test_enqueue_too_large_data() {
        let mut service = super::Service::new();
        assert!(service.queue_capacity < std::usize::MAX);
        assert!(service
            .on_enqueue(service.queue_capacity + 1, false)
            .is_err());
    }

    #[test]
    fn test_enqueue_full() {
        let mut service = super::Service::new();
        assert!(service.on_enqueue(service.queue_capacity, false).is_ok());
        assert!(service.on_enqueue(1, false).is_err());
    }

    #[test]
    fn test_dequeue() {
        let mut service = super::Service::new();
        assert_eq!(service.on_enqueue(10, false).unwrap(), 10);
        assert_eq!(service.on_dequeue(6, false), 4);
        assert_eq!(service.on_dequeue(3, false), 1);

        // queue size not enough.
        assert_eq!(service.on_dequeue(2, false), 0);
    }

    #[test]
    fn test_throttle() {
        let mut service = super::Service::new();

        // not throttled by default.
        assert!(service.check_throttling().is_ok());

        // throttled once more than max_throttle_queue_size data queued.
        let max = service.max_throttle_queue_size;
        assert_eq!(service.on_enqueue(max + 1, false).unwrap(), max + 1);
        assert!(service.check_throttling().is_err());

        // not throttled after some data dequeued.
        assert_eq!(service.on_dequeue(1, false), max);
        assert!(service.check_throttling().is_ok());
    }

    #[test]
    fn test_get_throttling_ratio() {
        let mut service = super::Service::new();

        // default ratio is 1.0
        assert_throttling_ratio(&service, 100);

        // no more than min_throttle_queue_size queued.
        let min = service.min_throttle_queue_size;
        assert_eq!(service.on_enqueue(min - 1, false).unwrap(), min - 1);
        assert_throttling_ratio(&service, 100);
        assert_eq!(service.on_enqueue(1, false).unwrap(), min);
        assert_throttling_ratio(&service, 100);

        // more than max_throttle_queue_size queued.
        assert_eq!(service.on_dequeue(min, false), 0);
        let max = service.max_throttle_queue_size;
        assert_eq!(service.on_enqueue(max, false).unwrap(), max);
        assert_throttling_ratio(&service, 0);
        assert_eq!(service.on_enqueue(1, false).unwrap(), max + 1);
        assert_throttling_ratio(&service, 0);

        // partial throttled
        assert_eq!(service.on_dequeue(max + 1, false), 0);
        assert!(service.on_enqueue(min + (max - min) / 2, false).is_ok());
        assert_throttling_ratio(&service, 50);
    }

    fn assert_throttling_ratio(service: &super::Service, percentage: usize) {
        assert!(percentage <= 100);
        let ratio = service.get_throttling_ratio() * 100.0;
        assert_eq!(ratio as usize, percentage);
    }
}
