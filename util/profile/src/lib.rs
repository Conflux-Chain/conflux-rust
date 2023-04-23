#[cfg(feature = "pprof-metrics")]
extern crate pprof;

#[cfg(feature = "pprof-metrics")]
use lazy_static::lazy_static;

#[cfg(feature = "pprof-metrics")]
lazy_static! {
    static ref PPROF: pprof::ProfilerGuard<'static> =
        pprof::ProfilerGuard::new(1000).unwrap();
}

pub fn initialize_pprof() {
    #[cfg(feature = "pprof-metrics")]
    {
        lazy_static::initialize(&PPROF);
    }
}

pub fn report_pprof() {
    #[cfg(feature = "pprof-metrics")]
    {
        use pprof::protos::Message;
        use std::{fs::File, io::Write};
        match PPROF.report().build() {
            Ok(report) => {
                let mut file = File::create("profile.pb").unwrap();
                let profile = report.pprof().unwrap();

                let mut content = Vec::new();
                profile.encode(&mut content).unwrap();
                file.write_all(&content).unwrap();
            }
            Err(_) => {}
        };
    }
}

#[cfg(all(feature = "timer-metrics", feature = "scope-metrics"))]
#[macro_export]
macro_rules! metric_record {
    ($timer:ident, $timer2:ident) => {
        let _timer = metrics::MeterTimer::time_func($timer.as_ref());
        let _timer2 = metrics::ScopeTimer::time_scope($timer2.as_ref());
    };
}

#[cfg(all(feature = "timer-metrics", not(feature = "scope-metrics")))]
#[macro_export]
macro_rules! metric_record {
    ($timer:ident, $timer2:ident) => {
        let _timer = metrics::MeterTimer::time_func($timer.as_ref());
        let _ = $timer2.as_ref();
    };
}

#[cfg(not(feature = "timer-metrics"))]
#[macro_export]
macro_rules! metric_record {
    ($timer:ident, $timer2:ident) => {};
}
