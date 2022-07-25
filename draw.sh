#!/bin/bash

cd tests/extra-test-toolkits || (echo 'cd fails' && exit)

function print_charts() {
    python -c "from tools.metrics_echarts import generate_metric_chart; generate_metric_chart('$1', metric_name=['lock','storage','system_metrics','timer'], filter=['.s15','expdec.mean'])"
}

export -f print_charts

rm ../../experiment_data/metrics/alpha/*.html
find ../../experiment_data/metrics/alpha | grep ".log$" | xargs -n 1 -I {} bash -c 'print_charts "$@"' _ {}
