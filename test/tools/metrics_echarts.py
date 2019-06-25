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

class Metric:
    def __init__(self, name:str):
        self.name = name
        self.timestamps = []

    @staticmethod
    def create_metric(metric_type, name):
        if metric_type == "Meter":
            return MetricMeter(name)
        else:
            return MetricGauge(name)

    def append(self, timestamp, metric):
        pass

    def add_yaxis(self, chart:Line):
        pass

class MetricGauge(Metric):
    def __init__(self, name:str):
        Metric.__init__(self, name)
        self.values = []

    def append(self, timestamp, metric):
        self.timestamps.append(timestamp)
        self.values.append(metric)

    def add_yaxis(self, chart:Line):
        chart.add_yaxis(None, self.values)

class MetricMeter(Metric):
    def __init__(self, name:str):
        Metric.__init__(self, name)
        self.m1 = []
        self.m5 = []
        self.m15 = []
        self.mean = []

    def append(self, timestamp, metric):
        self.timestamps.append(timestamp)
        self.m1.append(parse_value(metric, "m1: ", ","))
        self.m5.append(parse_value(metric, "m5: ", ","))
        self.m15.append(parse_value(metric, "m15: ", ","))
        self.mean.append(parse_value(metric, "mean: ", "}"))

    def add_yaxis(self, chart:Line):
        chart.add_yaxis("m1", self.m1)
        chart.add_yaxis("m5", self.m5)
        chart.add_yaxis("m15", self.m15)
        chart.add_yaxis("mean", self.mean)

def generate_metric_chart(metrics_log_file:str, metric_name:Optional[str]=None):
    assert os.path.exists(metrics_log_file), "metrics log file not found: {}".format(metrics_log_file)
    metrics = {}

    with open(metrics_log_file, "r", encoding="utf-8") as fp:
        for line in fp.readlines():
            fields = line[:-1].split(", ", 3)

            timestamp = fields[0]
            name = fields[1]
            metric_type = fields[2]
            value = fields[3]

            if metric_name is None or metric_name == name:
                if metrics.get(name) is None:
                    metrics[name] = Metric.create_metric(metric_type, name)

                metrics[name].append(timestamp, value)

    assert len(metrics) > 0, "metrics log file is empty" if metric_name is None else "metric name [{}] not found".format(metric_name)

    for (key, metric) in metrics.items():
        chart = (
            Line()
            .add_xaxis(metric.timestamps)
            .set_global_opts(title_opts=opts.TitleOpts(title=key))
        )

        metric.add_yaxis(chart)

        output_html_file = metrics_log_file + ".{}.html".format(key)
        print("[{}]: {}".format(key, output_html_file))
        chart.render(output_html_file)

if __name__ == "__main__":
    assert len(sys.argv) >= 2, "Parameter required: <metrics_log_file> [<metric_name>]"
    metrics_log_file = sys.argv[1]
    metric_name = None if len(sys.argv) == 2 else sys.argv[2]
    generate_metric_chart(metrics_log_file, metric_name)
