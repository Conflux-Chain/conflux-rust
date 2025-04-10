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
use lazy_static::lazy_static;
use log::{error, info};
use std::{
    convert::Infallible,
    fmt::{self, Write},
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::net::TcpListener;

use cfx_tasks::TaskExecutor;
use hyper::{server::conn::http1, service::service_fn, Response, StatusCode};
pub struct PrometheusReporter {
    listen_addr: SocketAddr,
    executor: TaskExecutor,
}

lazy_static! {
    static ref PREVIOUS_METRICS_SIZE: AtomicUsize = AtomicUsize::new(24576); // default size 24KB
}

impl PrometheusReporter {
    pub fn new(
        listen_addr: &str, executor: TaskExecutor,
    ) -> Result<Self, String> {
        let addr = listen_addr
            .parse()
            .map_err(|_| "Invalid prometheus listen address".to_string())?;
        Ok(PrometheusReporter {
            listen_addr: addr,
            executor,
        })
    }

    pub fn create_error_response(message: &str) -> Response<String> {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(message.to_string())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal Server Error".to_string())
                    .unwrap()
            })
    }

    pub fn start_http_server(&self) -> Result<(), String> {
        if !is_enabled() {
            return Err("Prometheus reporter is not enabled".to_string());
        }

        let listen_addr = self.listen_addr;

        self.executor.spawn_with_graceful_shutdown_signal(|mut signal| async move{

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
                let stream = tokio::select! {
                    _ = &mut signal => break,
                    io = listener.accept() => {
                        match io {
                            Ok((stream, _addr)) => stream,
                            Err(e) => {
                                error!("Failed to accept connection: {}", e);
                                continue;
                            }
                        }
                    }
                };

                let io = TokioIo::new(stream);

                let service = service_fn(|_req| async {
                    let metrics_data = match PrometheusReporter::collect_metrics() {
                        Ok(data) => data,
                        Err(e) => {
                            error!("Failed to collect metrics: {}", e);
                            return Ok::<_, Infallible>(
                                PrometheusReporter::create_error_response("Failed to collect metrics")
                            );
                        }
                    };
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            "content-type",
                            "text/plain; version=0.0.4",
                        )
                        .body(metrics_data)
                        .unwrap_or_else(|e| {
                            error!("Failed to create response: {}", e);
                            PrometheusReporter::create_error_response("Failed to create response")
                        });
                    Ok::<_, Infallible>(response)
                });

                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        error!("Error serving Prometheus connection: {}", err);
                    }
                });
            }
        });
        Ok(())
    }

    pub fn collect_metrics() -> Result<String, fmt::Error> {
        let capacity = PREVIOUS_METRICS_SIZE.load(Ordering::Relaxed);
        // Increase the buffer size by 25%
        let mut buffer = String::with_capacity(capacity + capacity / 4);

        let registry = DEFAULT_REGISTRY.read();

        for (name, metric) in registry.get_all() {
            let _ = metric.write_prometheus(name, None, &mut buffer)?;
        }

        let grouping_registry = DEFAULT_GROUPING_REGISTRY.read();
        for (group_name, metrics) in grouping_registry.get_all() {
            for (metric_name, metric) in metrics {
                let _ = metric.write_prometheus(
                    metric_name,
                    Some(group_name),
                    &mut buffer,
                )?;
            }
        }

        PREVIOUS_METRICS_SIZE.store(buffer.len(), Ordering::Relaxed);
        Ok(buffer)
    }
}
pub trait PrometheusReportable {
    fn write_prometheus(
        &self, name: &str, group: Option<&str>, buffer: &mut dyn Write,
    ) -> std::fmt::Result;
}
impl PrometheusReportable for CounterUsize {
    fn write_prometheus(
        &self, name: &str, group: Option<&str>, buffer: &mut dyn Write,
    ) -> std::fmt::Result {
        let full_name = group
            .map_or_else(|| name.to_string(), |g| format!("{}_{}", g, name));
        writeln!(buffer, "# HELP {} {}", full_name, full_name)?;
        writeln!(buffer, "# TYPE {} counter", full_name)?;
        writeln!(buffer, "{} {}", full_name, self.count())?;
        Ok(())
    }
}
impl PrometheusReportable for GaugeUsize {
    fn write_prometheus(
        &self, name: &str, group: Option<&str>, buffer: &mut dyn Write,
    ) -> std::fmt::Result {
        let full_name = group
            .map_or_else(|| name.to_string(), |g| format!("{}_{}", g, name));

        writeln!(buffer, "# HELP {} {}", full_name, full_name)?;
        writeln!(buffer, "# TYPE {} gauge", full_name)?;
        writeln!(buffer, "{} {}", full_name, self.value())?;
        Ok(())
    }
}
impl PrometheusReportable for StandardMeter {
    fn write_prometheus(
        &self, name: &str, group: Option<&str>, buffer: &mut dyn Write,
    ) -> std::fmt::Result {
        let base_name = group
            .map_or_else(|| name.to_string(), |g| format!("{}_{}", g, name));
        let snapshot = self.snapshot();
        // count (counter)
        let count_name = format!("{}_total", base_name);
        writeln!(buffer, "# HELP {} Total number of events.", count_name)?;
        writeln!(buffer, "# TYPE {} counter", count_name)?;
        writeln!(buffer, "{} {}", count_name, snapshot.count())?;
        // rates (gauge)
        let m1_name = format!("{}_m1_rate", base_name);

        writeln!(
            buffer,
            "# HELP {} One-minute exponentially-weighted moving average rate.",
            m1_name
        )?;
        writeln!(buffer, "# TYPE {} gauge", m1_name)?;
        writeln!(buffer, "{} {}", m1_name, snapshot.rate1())?;
        let m5_name = format!("{}_m5_rate", base_name);
        writeln!(
            buffer,
            "# HELP {} Five-minute exponentially-weighted moving average rate.",
            m5_name
        )?;
        writeln!(buffer, "# TYPE {} gauge", m5_name)?;
        writeln!(buffer, "{} {}", m5_name, snapshot.rate5())?;
        let m15_name = format!("{}_m15_rate", base_name);
        writeln!(buffer, "# HELP {} Fifteen-minute exponentially-weighted moving average rate.", m15_name)?;
        writeln!(buffer, "# TYPE {} gauge", m15_name)?;
        writeln!(buffer, "{} {}", m15_name, snapshot.rate15())?;
        let mean_name = format!("{}_mean_rate", base_name);
        writeln!(
            buffer,
            "# HELP {} Mean rate since the meter was created.",
            mean_name
        )?;
        writeln!(buffer, "# TYPE {} gauge", mean_name)?;
        writeln!(buffer, "{} {}", mean_name, snapshot.rate_mean())?;
        Ok(())
    }
}
impl<T: Histogram> PrometheusReportable for T {
    fn write_prometheus(
        &self, name: &str, group: Option<&str>, buffer: &mut dyn Write,
    ) -> std::fmt::Result {
        let base_name = group
            .map_or_else(|| name.to_string(), |g| format!("{}_{}", g, name));
        let snapshot = self.snapshot();

        writeln!(buffer, "# HELP {} {}", base_name, base_name)?;
        writeln!(buffer, "# TYPE {} summary", base_name)?;

        writeln!(buffer, "{}_count {}", base_name, snapshot.count())?;
        writeln!(buffer, "{}_sum {}", base_name, snapshot.sum())?;

        writeln!(buffer, "{}_min {}", base_name, snapshot.min())?;
        writeln!(buffer, "{}_max {}", base_name, snapshot.max())?;
        writeln!(buffer, "{}_mean {}", base_name, snapshot.mean())?;
        writeln!(buffer, "{}_stddev {}", base_name, snapshot.stddev())?;
        writeln!(buffer, "{}_variance {}", base_name, snapshot.variance())?;

        let quantiles = [0.5, 0.75, 0.9, 0.95, 0.99, 0.999];
        for q in quantiles.iter() {
            let value = snapshot.percentile(*q);
            writeln!(buffer, "{}{{quantile=\"{}\"}} {}", base_name, q, value)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{metrics, CounterUsize, GaugeUsize, Histogram, Meter};
    use cfx_tasks::TaskManager;
    use tokio::{net::TcpStream, time::timeout};

    async fn find_available_port() -> std::io::Result<u16> {
        TcpListener::bind("127.0.0.1:0")
            .await?
            .local_addr()
            .map(|addr| addr.port())
    }
    fn reset_registries() {
        DEFAULT_REGISTRY.write().clear();
        DEFAULT_GROUPING_REGISTRY.write().clear();
        metrics::enable()
    }

    async fn wait_for_server(
        addr: SocketAddr, wait_timeout: Duration,
    ) -> Result<(), String> {
        timeout(wait_timeout, async {
            loop {
                match TcpStream::connect(addr).await {
                    Ok(_) => return Ok(()),
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        })
        .await
        .map_err(|_| format!("Timeout while waiting for server to start"))?
    }
    #[tokio::test]
    async fn test_prometheus_endpoint() {
        reset_registries();

        let test_counter = CounterUsize::register("test_counter");

        test_counter.inc(1029);

        let test_gauge = GaugeUsize::register_with_group("api", "test_gauge");

        test_gauge.update(1029);

        let port = find_available_port()
            .await
            .expect("Failed to find free port");
        let listen_addr_str = format!("127.0.0.1:{}", port);

        let server_addr: SocketAddr = listen_addr_str.parse().unwrap();

        let tasks = TaskManager::current();
        let executor = tasks.executor();
        let reporter = PrometheusReporter::new(&listen_addr_str, executor)
            .expect("Failed to create Prometheus reporter");

        let _ = reporter.start_http_server().unwrap();

        wait_for_server(server_addr, Duration::from_secs(5))
            .await
            .expect("Failed to connect to server");

        let client = reqwest::Client::new();
        let response = match timeout(
            Duration::from_secs(2),
            client
                .get(format!("http://{}/metrics", listen_addr_str))
                .send(),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => panic!("Failed to send request: {}", e),
            Err(_) => panic!("Timeout while waiting for response"),
        };

        assert!(response.status().is_success());
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .unwrap(),
            "text/plain; version=0.0.4"
        );

        let body = response.text().await.unwrap();

        assert!(body.contains("# HELP test_counter test_counter"));
        assert!(body.contains("# TYPE test_counter counter"));
        assert!(body.contains("test_counter 1029"));

        assert!(body.contains("# HELP api_test_gauge api_test_gauge"));
        assert!(body.contains("# TYPE api_test_gauge gauge"));
        assert!(body.contains("api_test_gauge 1029"));
    }

    #[test]
    fn test_counter_prometheus() {
        let counter = CounterUsize::default();

        counter.inc(8);

        let mut buffer = String::new();

        let _ = counter
            .write_prometheus("test_counter", None, &mut buffer)
            .unwrap();
        assert!(buffer.contains("# HELP test_counter test_counter"));
        assert!(buffer.contains("# TYPE test_counter counter"));
        assert!(buffer.contains("test_counter 8"));

        buffer.clear();

        let _ = counter
            .write_prometheus("test_request_counter", Some("api"), &mut buffer)
            .unwrap();
        assert!(buffer.contains(
            "# HELP api_test_request_counter api_test_request_counter"
        ));
        assert!(buffer.contains("# TYPE api_test_request_counter counter"));
        assert!(buffer.contains("api_test_request_counter 8"));
    }

    #[test]
    fn test_gauge_prometheus() {
        let gauge = GaugeUsize::default();

        gauge.update(199);

        let mut buffer = String::new();
        let _ = gauge
            .write_prometheus("test_gauge", None, &mut buffer)
            .unwrap();
        assert!(buffer.contains("# HELP test_gauge test_gauge"));
        assert!(buffer.contains("# TYPE test_gauge gauge"));
        assert!(buffer.contains("test_gauge 199"));

        buffer.clear();

        let _ = gauge
            .write_prometheus("test_request_gauge", Some("node"), &mut buffer)
            .unwrap();
        assert!(buffer.contains(
            "# HELP node_test_request_gauge node_test_request_gauge"
        ));
        assert!(buffer.contains("# TYPE node_test_request_gauge gauge"));
        assert!(buffer.contains("node_test_request_gauge 199"));
    }

    #[test]
    fn test_meter_prometheus() {
        let meter = StandardMeter::new("test_meter".into());
        meter.mark(11);

        let mut buffer = String::new();

        // if use the meter.write_prometheus("test_meter", None, &mut buffer);
        let _ = meter
            .write_prometheus("test_meter", None, &mut buffer)
            .unwrap();
        // PrometheusReportable::write_prometheus(&meter, "test_meter", None,
        // &mut buffer);
        assert!(
            buffer.contains("# HELP test_meter_total Total number of events.")
        );
        assert!(buffer.contains("# TYPE test_meter_total counter"));
        assert!(buffer.contains("test_meter_total 11"));

        assert!(buffer.contains("# HELP test_meter_m1_rate One-minute exponentially-weighted moving average rate."));
        assert!(buffer.contains("# TYPE test_meter_m1_rate gauge"));
        assert!(buffer.contains("test_meter_m1_rate 0"));

        assert!(buffer.contains("# HELP test_meter_m5_rate Five-minute exponentially-weighted moving average rate."));
        assert!(buffer.contains("# TYPE test_meter_m5_rate gauge"));
        assert!(buffer.contains("test_meter_m5_rate 0"));

        assert!(buffer.contains("# HELP test_meter_m15_rate Fifteen-minute exponentially-weighted moving average rate."));
        assert!(buffer.contains("# TYPE test_meter_m15_rate gauge"));
        assert!(buffer.contains("test_meter_m15_rate 0"));

        assert!(buffer.contains("# HELP test_meter_mean_rate Mean rate since the meter was created."));
        assert!(buffer.contains("# TYPE test_meter_mean_rate gauge"));
        assert!(buffer.contains("test_meter_mean_rate"));

        buffer.clear();

        let _ = meter
            .write_prometheus("test_request_meter", Some("node"), &mut buffer)
            .unwrap();
        assert!(buffer.contains(
            "# HELP node_test_request_meter_total Total number of events."
        ));
        assert!(buffer.contains("# TYPE node_test_request_meter_total counter"));
        assert!(buffer.contains("node_test_request_meter_total 11"));

        assert!(buffer.contains("# HELP node_test_request_meter_m1_rate One-minute exponentially-weighted moving average rate."));
        assert!(buffer.contains("# TYPE node_test_request_meter_m1_rate gauge"));
        assert!(buffer.contains("node_test_request_meter_m1_rate 0"));
        assert!(buffer.contains("# HELP node_test_request_meter_m5_rate Five-minute exponentially-weighted moving average rate."));
        assert!(buffer.contains("# TYPE node_test_request_meter_m5_rate gauge"));
        assert!(buffer.contains("node_test_request_meter_m5_rate 0"));
        assert!(buffer.contains("# HELP node_test_request_meter_m15_rate Fifteen-minute exponentially-weighted moving average rate."));
        assert!(
            buffer.contains("# TYPE node_test_request_meter_m15_rate gauge")
        );
        assert!(buffer.contains("node_test_request_meter_m15_rate 0"));
        assert!(buffer.contains("# HELP node_test_request_meter_mean_rate Mean rate since the meter was created."));
        assert!(
            buffer.contains("# TYPE node_test_request_meter_mean_rate gauge")
        );
        assert!(buffer.contains("node_test_request_meter_mean_rate"));
    }

    #[test]
    fn test_histogram_prometheus() {
        let histogram = crate::histogram::UniformSample::new(99);
        histogram.update(1);
        histogram.update(2);
        histogram.update(10);
        histogram.update(100);
        histogram.update(1000);

        let mut buffer = String::new();

        let _ = histogram
            .write_prometheus("test_histogram", None, &mut buffer)
            .unwrap();

        assert!(buffer.contains("# HELP test_histogram test_histogram"));
        assert!(buffer.contains("# TYPE test_histogram summary"));
        assert!(buffer.contains("test_histogram_count 5"));
        assert!(buffer.contains("test_histogram_sum 1113"));
        assert!(buffer.contains("test_histogram{quantile=\"0.5\"}"));
        assert!(buffer.contains("test_histogram{quantile=\"0.75\"}"));
        assert!(buffer.contains("test_histogram{quantile=\"0.9\"}"));
        assert!(buffer.contains("test_histogram{quantile=\"0.99\"}"));
        assert!(buffer.contains("test_histogram{quantile=\"0.999\"}"));

        buffer.clear();

        let _ = histogram
            .write_prometheus(
                "test_request_histogram",
                Some("node"),
                &mut buffer,
            )
            .unwrap();

        assert!(buffer.contains(
            "# HELP node_test_request_histogram node_test_request_histogram"
        ));
        assert!(buffer.contains("# TYPE node_test_request_histogram summary"));
        assert!(buffer.contains("node_test_request_histogram_count 5"));
        assert!(buffer.contains("node_test_request_histogram_sum 1113"));
        assert!(
            buffer.contains("node_test_request_histogram{quantile=\"0.5\"}")
        );
        assert!(
            buffer.contains("node_test_request_histogram{quantile=\"0.75\"}")
        );
        assert!(
            buffer.contains("node_test_request_histogram{quantile=\"0.9\"}")
        );
        assert!(
            buffer.contains("node_test_request_histogram{quantile=\"0.99\"}")
        );
        assert!(
            buffer.contains("node_test_request_histogram{quantile=\"0.999\"}")
        );
    }
}
