#!/usr/bin/env python3

import sys
import os
from typing import Optional

from pyecharts.charts import Line
from pyecharts import options as opts

def parse_value(log_line:str, prefix:str, suffix:str):
    start = 0 if prefix is None else log_line.index(prefix) + len(prefix)
    end = len(log_line) if suffix is None else log_line.index(suffix, start)
    return log_line[start:end]

def generate_metric_chart(metrics_log_file:str, metric_name:Optional[str]=None):
    assert os.path.exists(metrics_log_file), "metrics log file not found: {}".format(metrics_log_file)
    metrics = {}

    with open(metrics_log_file, "r", encoding="utf-8") as fp:
        for line in fp.readlines():
            fields = line[:-1].split(", ")
            assert len(fields) == 4, "invalid metric line: " + line[:-1]

            timestamp = fields[0]
            name = fields[1]
            value = fields[3]

            if metric_name is None or metric_name == name:
                if metrics.get(name) is None:
                    metrics[name] = ([], [])

                metrics[name][0].append(timestamp)
                metrics[name][1].append(value)

    assert len(metrics) > 0, "metrics log file is empty" if metric_name is None else "metric name [{}] not found".format(metric_name)

    for (key, (timestamps, values)) in metrics.items():
        chart = (
            Line()
            .add_xaxis(timestamps)
            .add_yaxis(None, values)
            .set_global_opts(title_opts=opts.TitleOpts(title=key))
        )

        output_html_file = metrics_log_file + ".{}.html".format(key)
        print("[{}]: {}".format(key, output_html_file))
        chart.render(output_html_file)

if __name__ == "__main__":
    assert len(sys.argv) >= 2, "Parameter required: <metrics_log_file> [<metric_name>]"
    metrics_log_file = sys.argv[1]
    metric_name = None if len(sys.argv) == 2 else sys.argv[2]
    generate_metric_chart(metrics_log_file, metric_name)
