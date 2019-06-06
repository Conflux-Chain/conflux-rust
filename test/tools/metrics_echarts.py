import sys
import os
from typing import Dict, List, Tuple

from pyecharts.charts import Line
from pyecharts import options as opts

def parse_value(log_line:str, prefix:str, suffix:str):
    start = 0 if prefix is None else log_line.index(prefix) + len(prefix)
    end = len(log_line) if suffix is None else log_line.index(suffix, start)
    return log_line[start:end]

assert len(sys.argv) >= 2, "Parameter required: <metrics_log> [<metric_name>]"
metrics_log_file = sys.argv[1]
metric_name = None if len(sys.argv) == 2 else sys.argv[2]

metrics = {}

with open(metrics_log_file, "r", encoding="utf-8") as fp:
    for line in fp.readlines():
        line = line[:-1]

        timestamp = parse_value(line, None, ", ")
        name = parse_value(line, "name: \"", "\"")
        value = parse_value(line, "value: ", "}")

        if metric_name is None or metric_name == name:
            if metrics.get(name) is None:
                metrics[name] = ([], [])

            metrics[name][0].append(timestamp)
            metrics[name][1].append(value)

assert len(metrics) > 0, "metric not found"

for (key, (timestamps, values)) in metrics.items():
    chart = (
        Line()
        .add_xaxis(timestamps)
        .add_yaxis(None, values)
        .set_global_opts(title_opts=opts.TitleOpts(title=key))
    )

    output_html = os.path.abspath("metrics.{}.html".format(key))
    print("[{}]: {}".format(key, output_html))
    chart.render(output_html)