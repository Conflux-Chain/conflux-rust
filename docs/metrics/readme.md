# Observability with Influxdb(v1.8) & Grafana

Conflux-rust supports running metrics data collection on nodes. The data currently collected includes transaction pool, RPC requests, network status, etc.

The collected data needs to be stored using InfluxDB (v1.8) and can then be displayed through Grafana by configuring dashboards.

## Enabling Node Metrics Configuration

Set the following configuration items in the node's configuration file (hydra.toml or testnet.toml):

```toml
rpc_enable_metrics=true
metrics_enabled=true
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

## FAQs

1. Does it support InfluxDB 2.0 or Prometheus?

    Currently, only InfluxDB 1.8 is supported. There are plans to consider supporting InfluxDB 2.0 or Prometheus in the future.