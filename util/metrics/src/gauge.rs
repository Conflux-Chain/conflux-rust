use crate::is_enabled;
use prometheus;

pub struct Gauge {
    inner: Option<prometheus::IntGauge>,
}

impl Gauge {
    pub fn register(key: &'static str) -> Self {
        if !is_enabled() {
            return Gauge { inner: None };
        }

        let gauge = prometheus::IntGauge::new(key, " ").unwrap();
        prometheus::default_registry()
            .register(Box::new(gauge.clone()))
            .unwrap();

        Gauge { inner: Some(gauge) }
    }

    pub fn inc(&self) {
        if let Some(ref gauge) = self.inner {
            gauge.inc();
        }
    }

    pub fn dec(&self) {
        if let Some(ref gauge) = self.inner {
            gauge.dec();
        }
    }

    pub fn add(&self, delta: i64) {
        if let Some(ref gauge) = self.inner {
            gauge.add(delta);
        }
    }

    pub fn sub(&self, delta: i64) {
        if let Some(ref gauge) = self.inner {
            gauge.sub(delta);
        }
    }

    pub fn update(&self, value: i64) {
        if let Some(ref gauge) = self.inner {
            gauge.set(value);
        }
    }
}
