#!/usr/bin/env python3

import sys
import os
import tarfile

from metrics_echarts import parse_value, generate_metric_chart
from pyecharts.charts import Line
from pyecharts import options as opts

assert len(sys.argv) >= 2, "Parameter required: <exp_archive> [<output_dir>]"
exp_archive_file = sys.argv[1]
assert os.path.exists(exp_archive_file), "Experiment archive file not found"
output_dir = "exp_metrics" if len(sys.argv) == 2 else sys.argv[2]
output_dir = os.path.abspath(output_dir)
if not os.path.exists(output_dir):
    os.makedirs(output_dir, exist_ok=True)

# decompress the archive from experiment
with tarfile.open(exp_archive_file, "r:gz") as tar_file:
    tar_file.extractall(output_dir)

# generate charts for latency
latency_stat_file = os.path.join(output_dir, "exp_stat_latency.log")
assert os.path.exists(latency_stat_file), "Latency statistics file not found: {}".format(latency_stat_file)

tags = []
latencies = {}

with open(latency_stat_file, "r", encoding="utf-8") as fp:
    for line in fp.readlines():
        line = line[:-1]
        fields = [f.strip() for f in line.split("|")]
        if len(fields) == 11:
            if fields[2] == "Avg":
                tags.append(fields[1].replace("_", "\n"))
            elif "block broadcast latency" in fields[1] and (
                "/P90)" in fields[1] or "/P95)" in fields[1] or "/P99)" in fields[1]
            ):
                metric = parse_value(fields[1], "block broadcast latency (", ")")
                if not latencies.get(metric):
                    latencies[metric] = []
                latencies[metric].append(fields[2])     # fields[2] = Avg

chart = (
    Line()
    .add_xaxis(tags)
    .set_global_opts(
        title_opts=opts.TitleOpts(title="Block Broadcast Latency (Average)"),
        legend_opts=opts.LegendOpts(orient="vertical", pos_left="right", pos_top="middle"),
    )
)

for (metric, values) in latencies.items():
    chart.add_yaxis(metric, values, is_selected="P99" in metric)

output_html = os.path.join(output_dir, "exp_stat_latency.log.html")
print("[exp_stat_latency]: {}".format(output_html))
chart.render(output_html)

# generate charts for metrics
for (path, _, files) in os.walk(output_dir):
    for f in files:
        if f.endswith(".metrics.log"):
            metric_log_file = os.path.join(path, f)
            generate_metric_chart(metric_log_file)
