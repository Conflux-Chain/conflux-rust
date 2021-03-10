// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{register_meter_with_group, Meter};
use parking_lot::{
    Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Instant,
};

/// Metric type for locks, e.g. `Mutex` and `RwLock`.
pub struct Lock {
    acquire_tps: Arc<dyn Meter>, // lock acquires per second
    wait_time: Arc<dyn Meter>,   // lock wait time per second
    hold_time: Arc<dyn Meter>,   // lock hold time per second
}

impl Lock {
    pub fn register(name: &str) -> Self {
        Lock {
            acquire_tps: register_meter_with_group(name, "acquires"),
            wait_time: register_meter_with_group(name, "wait_t"),
            hold_time: register_meter_with_group(name, "hold_t"),
        }
    }
}

pub trait MutexExtensions<T> {
    fn lock_with_metric(&self, metric: &Lock) -> MutexGuardWithMetrics<'_, T>;
}

impl<T> MutexExtensions<T> for Mutex<T> {
    fn lock_with_metric(&self, metric: &Lock) -> MutexGuardWithMetrics<'_, T> {
        metric.acquire_tps.mark(1);
        let start = Instant::now();
        let guard = self.lock();
        metric.wait_time.mark(start.elapsed().as_nanos() as usize);
        MutexGuardWithMetrics::new(guard, metric.hold_time.clone())
    }
}

pub trait RwLockExtensions<T> {
    fn read_with_metric(
        &self, metric: &Lock,
    ) -> RwLockReadGuardWithMetrics<'_, T>;
    fn write_with_metric(
        &self, metric: &Lock,
    ) -> RwLockWriteGuardWithMetrics<'_, T>;
}

impl<T> RwLockExtensions<T> for RwLock<T> {
    fn read_with_metric(
        &self, metric: &Lock,
    ) -> RwLockReadGuardWithMetrics<'_, T> {
        metric.acquire_tps.mark(1);
        let start = Instant::now();
        let guard = self.read();
        metric.wait_time.mark(start.elapsed().as_nanos() as usize);
        RwLockReadGuardWithMetrics::new(guard, metric.hold_time.clone())
    }

    fn write_with_metric(
        &self, metric: &Lock,
    ) -> RwLockWriteGuardWithMetrics<'_, T> {
        metric.acquire_tps.mark(1);
        let start = Instant::now();
        let guard = self.write();
        metric.wait_time.mark(start.elapsed().as_nanos() as usize);
        RwLockWriteGuardWithMetrics::new(guard, metric.hold_time.clone())
    }
}

pub type MutexGuardWithMetrics<'a, T> = LockGuard<MutexGuard<'a, T>>;
pub type RwLockReadGuardWithMetrics<'a, T> = LockGuard<RwLockReadGuard<'a, T>>;
pub type RwLockWriteGuardWithMetrics<'a, T> =
    LockGuard<RwLockWriteGuard<'a, T>>;

pub struct LockGuard<GUARD> {
    raw: GUARD,
    start: Instant,
    lock_hold_time: Arc<dyn Meter>,
}

impl<GUARD> LockGuard<GUARD> {
    fn new(raw: GUARD, lock_hold_time: Arc<dyn Meter>) -> Self {
        LockGuard {
            raw,
            start: Instant::now(),
            lock_hold_time,
        }
    }
}

impl<GUARD> Drop for LockGuard<GUARD> {
    fn drop(&mut self) {
        let elapsed_nano = self.start.elapsed().as_nanos() as usize;
        self.lock_hold_time.mark(elapsed_nano);
    }
}

impl<T, GUARD: Deref<Target = T>> Deref for LockGuard<GUARD> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.raw
    }
}

impl<T, GUARD: DerefMut<Target = T>> DerefMut for LockGuard<GUARD> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.raw
    }
}
