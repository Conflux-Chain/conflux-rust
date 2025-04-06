// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    counter::{Counter, CounterUsize},
    gauge::{Gauge, GaugeUsize},
    histogram::Histogram,
    meter::{Meter, StandardMeter},
    metrics::is_enabled,
    registry::{DEFAULT_GROUPING_REGISTRY, DEFAULT_REGISTRY},
};
use hyper_util::rt::TokioIo;
use log::{error, info};
use std::{convert::Infallible, net::SocketAddr, thread};
use tokio::{net::TcpListener, runtime};

use hyper::{server::conn::http1, service::service_fn, Response, StatusCode};
pub struct PrometheusReporter {
    listen_addr: SocketAddr,
}

impl PrometheusReporter {
    pub fn new(listen_addr: &str) -> Result<Self, String> {
        let addr = listen_addr
            .parse()
            .map_err(|_| "Invalid prometheus listen address".to_string())?;
        Ok(PrometheusReporter { listen_addr: addr })
    }

    pub fn start_http_server(&self) {
        if !is_enabled() {
            return;
        }

        let listen_addr = self.listen_addr;

        let _ = thread::spawn(move || {
            let rt = match runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!("Failed to create Tokio runtime for Prometheus server: {}", e);
                    return;
                }
            };

            rt.block_on(async move {
                let listener = match TcpListener::bind(listen_addr).await {
                    Ok(listener) => {
                        info!("Prometheus server listening on {}", listen_addr);
                        listener
                    }
                    Err(e) => {
                        error!(
                            "Failed to bind Prometheus server to address {}: {}",
                            listen_addr, e
                        );
                        return;
                    }
                };

                loop {
                    match listener.accept().await {
                        Ok((stream, _addr)) => {
                            let io = TokioIo::new(stream);

                            let service = service_fn(|_req| async {
                                let metrics_data = collect_metrics();

                                let response = Response::builder()
                                    .status(StatusCode::OK)
                                    .header(
                                        "content-type",
                                        "text/plain; version=0.0.4",
                                    )
                                    .body(metrics_data)
                                    .unwrap_or_else(|e| {
                                        error!("Failed to create response: {}", e);
                                        Response::builder()
                                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                                            .body("Internal Server Error".into())
                                            .unwrap()
                                    });

                                Ok::<_, Infallible>(response)
                            });


                            tokio::spawn(async move {
                                if let Err(err) = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                                    error!("Error serving Prometheus connection: {}", err);
                                }
                            });

                        }
                        Err(e) => {
                            error!("Failed to accept connection for Prometheus server: {}", e);
                            continue;
                        }
                    }
                }
            });
        });
    }
}

fn collect_metrics() -> String {
    let mut buffer = String::new();

    let registry = DEFAULT_REGISTRY.read();

    for (name, metric) in registry.get_all() {
        metric.write_prometheus(name, None, &mut buffer);
    }

    let grouping_registry = DEFAULT_GROUPING_REGISTRY.read();
    for (group_name, metrics) in grouping_registry.get_all() {
        for (metric_name, metric) in metrics {
            metric.write_prometheus(metric_name, Some(group_name), &mut buffer);
        }
    }

    buffer
}

pub trait PrometheusReportable {
    fn write_prometheus(
        &self, name: &str, group: Option<&str>, buffer: &mut String,
    );
}

impl PrometheusReportable for CounterUsize {
    fn write_prometheus(
        &self, name: &str, group: Option<&str>, buffer: &mut String,
    ) {
        let full_name = group
            .map_or_else(|| name.to_string(), |g| format!("{}_{}", g, name));
        buffer.push_str(&format!("# HELP {} {}\n", full_name, full_name));
        buffer.push_str(&format!("# TYPE {} counter\n", full_name));
        buffer.push_str(&format!("{} {}\n", full_name, self.count()));
    }
}

impl PrometheusReportable for GaugeUsize {
    fn write_prometheus(
        &self, name: &str, group: Option<&str>, buffer: &mut String,
    ) {
        let full_name = group
            .map_or_else(|| name.to_string(), |g| format!("{}_{}", g, name));

        buffer.push_str(&format!("# HELP {} {}\n", full_name, full_name));
        buffer.push_str(&format!("# TYPE {} gauge\n", full_name));
        buffer.push_str(&format!("{} {}\n", full_name, self.value()));
    }
}

impl PrometheusReportable for StandardMeter {
    fn write_prometheus(
        &self, name: &str, group: Option<&str>, buffer: &mut String,
    ) {
        let base_name = group
            .map_or_else(|| name.to_string(), |g| format!("{}_{}", g, name));

        let snapshot = self.snapshot();

        // count (counter)
        let count_name = format!("{}_total", base_name);
        buffer.push_str(&format!(
            "# HELP {} Total number of events.\n",
            count_name
        ));
        buffer.push_str(&format!("# TYPE {} counter\n", count_name));
        buffer.push_str(&format!("{} {}\n", count_name, snapshot.count()));

        // rates (gauge)
        let m1_name = format!("{}_m1_rate", base_name);
        buffer.push_str(&format!("# HELP {} One-minute exponentially-weighted moving average rate.\n", m1_name));
        buffer.push_str(&format!("# TYPE {} gauge\n", m1_name));
        buffer.push_str(&format!("{} {}\n", m1_name, snapshot.rate1()));

        let m5_name = format!("{}_m5_rate", base_name);
        buffer.push_str(&format!("# HELP {} Five-minute exponentially-weighted moving average rate.\n", m5_name));
        buffer.push_str(&format!("# TYPE {} gauge\n", m5_name));
        buffer.push_str(&format!("{} {}\n", m5_name, snapshot.rate5()));

        let m15_name = format!("{}_m15_rate", base_name);
        buffer.push_str(&format!("# HELP {} Fifteen-minute exponentially-weighted moving average rate.\n", m15_name));
        buffer.push_str(&format!("# TYPE {} gauge\n", m15_name));
        buffer.push_str(&format!("{} {}\n", m15_name, snapshot.rate15()));

        let mean_name = format!("{}_mean_rate", base_name);
        buffer.push_str(&format!(
            "# HELP {} Mean rate since the meter was created.\n",
            mean_name
        ));
        buffer.push_str(&format!("# TYPE {} gauge\n", mean_name));
        buffer.push_str(&format!("{} {}\n", mean_name, snapshot.rate_mean()));
    }
}

impl<T: Histogram> PrometheusReportable for T {
    fn write_prometheus(
        &self, name: &str, group: Option<&str>, buffer: &mut String,
    ) {
        let base_name = group
            .map_or_else(|| name.to_string(), |g| format!("{}_{}", g, name));
        let snapshot = self.snapshot();

        buffer.push_str(&format!("# HELP {} {}\n", base_name, base_name));
        buffer.push_str(&format!("# TYPE {} summary\n", base_name));

        buffer.push_str(&format!("{}_count {}\n", base_name, snapshot.count()));
        buffer.push_str(&format!("{}_sum {}\n", base_name, snapshot.sum()));

        let quantiles = [0.5, 0.75, 0.9, 0.95, 0.99, 0.999];
        for q in quantiles.iter() {
            let value = snapshot.percentile(*q);
            buffer.push_str(&format!(
                "{}{{quantile=\"{}\"}} {}\n",
                base_name, q, value
            ));
        }
    }
}
