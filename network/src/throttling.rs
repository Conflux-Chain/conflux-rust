// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{Error, ErrorKind, ThrottlingReason};
use byte_unit::n_mb_bytes;
use lazy_static::lazy_static;
use parking_lot::RwLock;

lazy_static! {
    pub static ref THROTTLING_SERVICE: RwLock<Service> =
        RwLock::new(Service::new());
}

#[derive(Debug)]
pub struct Service {
    queue_capacity: usize,
    min_throttle_queue_size: usize,
    max_throttle_queue_size: usize,
    cur_queue_size: usize,
}

impl Service {
    fn new() -> Service {
        Service {
            queue_capacity: n_mb_bytes!(256) as usize,
            min_throttle_queue_size: n_mb_bytes!(10) as usize,
            max_throttle_queue_size: n_mb_bytes!(64) as usize,
            cur_queue_size: 0,
        }
    }

    pub fn initialize(
        &mut self, cap_mb: usize, min_throttle_mb: usize,
        max_throttle_mb: usize,
    )
    {
        // 0 < min_throttle_mb < max_throttle_mb < cap_mb
        assert!(cap_mb > max_throttle_mb);
        assert!(max_throttle_mb > min_throttle_mb);
        assert!(min_throttle_mb > 0);

        // capacity cannot overflow with usize type.
        let mb = n_mb_bytes!(1) as usize;
        assert!(std::usize::MAX / mb >= cap_mb);

        // ensure the currenet queue size will not exceed the capacity.
        let cap = cap_mb * mb;
        assert!(self.cur_queue_size <= cap);

        self.queue_capacity = cap;
        self.min_throttle_queue_size = min_throttle_mb * mb;
        self.max_throttle_queue_size = max_throttle_mb * mb;
    }

    pub(crate) fn on_enqueue(
        &mut self, data_size: usize,
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
        trace!(
            "throttling.on_enqueue: queue size = {}",
            self.cur_queue_size
        );

        Ok(self.cur_queue_size)
    }

    pub(crate) fn on_dequeue(&mut self, data_size: usize) -> usize {
        if data_size > self.cur_queue_size {
            error!("throttling.on_dequeue: dequeue too much data, data size = {}, queue size = {}", data_size, self.cur_queue_size);
            self.cur_queue_size = 0;
        } else {
            self.cur_queue_size -= data_size;
        }

        trace!(
            "throttling.on_dequeue: queue size = {}",
            self.cur_queue_size
        );

        self.cur_queue_size
    }

    pub fn check_throttling(&self) -> Result<(), Error> {
        if self.cur_queue_size > self.max_throttle_queue_size {
            debug!("throttling.check_throttling: throttled, queue size = {}, max throttling size = {}", self.cur_queue_size, self.max_throttle_queue_size);
            bail!(ErrorKind::Throttling(ThrottlingReason::Throttled));
        }

        Ok(())
    }

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
        assert_eq!(service.on_enqueue(10).unwrap(), 10);
        assert_eq!(service.on_enqueue(20).unwrap(), 30);

        // enqueue data size is 0.
        assert_eq!(service.on_enqueue(0).unwrap(), 30);
    }

    #[test]
    fn test_enqueue_too_large_data() {
        let mut service = super::Service::new();
        assert!(service.queue_capacity < std::usize::MAX);
        assert!(service.on_enqueue(service.queue_capacity + 1).is_err());
    }

    #[test]
    fn test_enqueue_full() {
        let mut service = super::Service::new();
        assert!(service.on_enqueue(service.queue_capacity).is_ok());
        assert!(service.on_enqueue(1).is_err());
    }

    #[test]
    fn test_dequeue() {
        let mut service = super::Service::new();
        assert_eq!(service.on_enqueue(10).unwrap(), 10);
        assert_eq!(service.on_dequeue(6), 4);
        assert_eq!(service.on_dequeue(3), 1);

        // queue size not enough.
        assert_eq!(service.on_dequeue(2), 0);
    }

    #[test]
    fn test_throttle() {
        let mut service = super::Service::new();

        // not throttled by default.
        assert!(service.check_throttling().is_ok());

        // throttled once more than max_throttle_queue_size data queued.
        let max = service.max_throttle_queue_size;
        assert_eq!(service.on_enqueue(max + 1).unwrap(), max + 1);
        assert!(service.check_throttling().is_err());

        // not throttled after some data dequeued.
        assert_eq!(service.on_dequeue(1), max);
        assert!(service.check_throttling().is_ok());
    }

    #[test]
    fn test_get_throttling_ratio() {
        let mut service = super::Service::new();

        // default ratio is 1.0
        assert_throttling_ratio(&service, 100);

        // no more than min_throttle_queue_size queued.
        let min = service.min_throttle_queue_size;
        assert_eq!(service.on_enqueue(min - 1).unwrap(), min - 1);
        assert_throttling_ratio(&service, 100);
        assert_eq!(service.on_enqueue(1).unwrap(), min);
        assert_throttling_ratio(&service, 100);

        // more than max_throttle_queue_size queued.
        assert_eq!(service.on_dequeue(min), 0);
        let max = service.max_throttle_queue_size;
        assert_eq!(service.on_enqueue(max).unwrap(), max);
        assert_throttling_ratio(&service, 0);
        assert_eq!(service.on_enqueue(1).unwrap(), max + 1);
        assert_throttling_ratio(&service, 0);

        // partial throttled
        assert_eq!(service.on_dequeue(max + 1), 0);
        assert!(service.on_enqueue(min + (max - min) / 2).is_ok());
        assert_throttling_ratio(&service, 50);
    }

    fn assert_throttling_ratio(service: &super::Service, percentage: usize) {
        assert!(percentage <= 100);
        let ratio = service.get_throttling_ratio() * 100.0;
        assert_eq!(ratio as usize, percentage);
    }
}
