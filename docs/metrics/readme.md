# Observability with Conflux-rust: InfluxDB (v1.8) / Prometheus & Grafana

Conflux-rust supports running metrics data collection on nodes. The data currently collected includes transaction pool, RPC requests, network status, etc. This data can be exported using two primary methods: pushing to an **InfluxDB (v1.8)** instance or exposing metrics via a **Prometheus** endpoint. The collected data can then be visualized using Grafana by configuring dashboards connected to your chosen data source.


## Configuring Metrics for InfluxDB (v1.8)

Set the following configuration items in the node's configuration file (hydra.toml or testnet.toml):

```toml
# Enable metrics collection
metrics_enabled=true
# Enable metrics for RPC
rpc_enable_metrics=true

# INfluxDb settings:
metrics_influxdb_host=x.x.x.x # change to your influxdb host
metrics_influxdb_db=db_name
metrics_influxdb_username=user_name
metrics_influxdb_password=user_password
metrics_report_interval_ms=30000
metrics_influxdb_node="a custom node name e.g. rpc1"
```

## Grafana Configuration Template

We provide a Grafana template that can be directly imported into Grafana to display the node's metrics data.

- [TransactionPool](https://github.com/Conflux-Chain/conflux-docker/blob/master/misc/grafana-config-template/TransactionPool.json)
- [ConfluxNode](https://github.com/Conflux-Chain/conflux-docker/blob/master/misc/grafana-config-template/TransactionPool.json)

Please refer to the documentation for setting up InfluxDB and Grafana services.

## Prometheus

Set the following configuration items in the node's configuration file (hydra.toml or testnet.toml):

```toml
# Enable metrics collection
metrics_enabled=true
# Enable metrics for RPC
rpc_enable_metrics=true
# Prometheus
metrics_prometheus_listen_addr="127.0.0.1:9777" # change to your port
```

## FAQs

1. Does it support InfluxDB 2.0?

    Currently, only InfluxDB 1.8 is supported. There are plans to consider supporting InfluxDB 2.0.