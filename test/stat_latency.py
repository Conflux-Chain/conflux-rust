#!/usr/bin/env python3

import csv
import os
import sys
import dateutil.parser
import time
from concurrent.futures import ThreadPoolExecutor
from prettytable import PrettyTable
from stat_latency_map_reduce import BlockLatencyType, Percentile, Statistics, HostLogReducer, LogAggregator
import stat_latency_map_reduce
from recompute import compute_latency


class Table:

    def __init__(self, header: list):
        self.header = header
        self.rows = []

    def add_row(self, row: list):
        assert len(row) == len(self.header), "row and header length mismatch"
        self.rows.append(row)

    def pretty_print(self):
        table = PrettyTable()
        table.field_names = self.header

        for row in self.rows:
            table.add_row(row)

        print(table)

    def output_csv(self, output_file: str):
        with open(output_file, "w", newline='') as fp:
            writer = csv.writer(fp)
            writer.writerow(self.header)
            for row in self.rows:
                writer.writerow(row)

    @staticmethod
    def new_matrix(name: str):
        header = [name]

        for p in Percentile:
            if p is not Percentile.Min:
                header.append(p.name)

        return Table(header)

    def add_data(self, name: str, data_format: str, data: list):
        self.add_stat(name, data_format, Statistics(data))

    def add_stat(self, name: str, data_format: str, stat: Statistics):
        row = [name]

        for p in Percentile:
            if p is Percentile.Avg:
                row.append(stat.get(p))
            elif p is not Percentile.Min:
                row.append(stat.get(p, data_format))

        self.add_row(row)


class LogAnalyzer:

    def __init__(self, stat_name: str, log_dir: str, csv_output: str):
        self.stat_name = stat_name
        self.log_dir = log_dir
        self.csv_output = csv_output

    def analyze(self):
        self.agg = LogAggregator.load(self.log_dir)

        print("{} blocks generated".format(len(self.agg.blocks)))

        self.agg.validate()
        self.agg.generate_latency_stat()

        table = Table.new_matrix(self.stat_name)

        for t in BlockLatencyType:
            for p in [Percentile.P80, Percentile.P90, Percentile.P95, Percentile.P99, Percentile.Max]:
                name = "block broadcast latency ({}/{})".format(t.name, p.name)
                table.add_stat(name, "%.2f", self.agg.stat_latency(t, p))

        block_timestamp_list = []
        referee_count_list = []
        for block in self.agg.blocks.values():
            block_timestamp_list.append(block.timestamp)
            referee_count_list.append(len(block.referees))

        table.add_data("block referees", "%d", referee_count_list)

        block_timestamp_list.sort()
        intervals = []
        for i in range(1, len(block_timestamp_list)):
            intervals.append(block_timestamp_list[
                             i] - block_timestamp_list[i - 1])
        table.add_data("block generation interval", "%.2f", intervals)

        table.pretty_print()
        if self.csv_output is not None:
            table.output_csv(self.csv_output)

if __name__ == "__main__":
    log_dir = sys.argv[1]
    final_block = sys.argv[2]
    aim_blocks = [sys.argv[3]]
    stat_latency_map_reduce.main(
        log_dir, os.path.join(log_dir, "blocks.log"))

    agg = LogAggregator.load(log_dir)
    parents = {}
    refs = {}
    generate_times = {}
    received_times = {}
    difficulties = {}

    lat_array = []
    for block in agg.blocks.values():
        if len(block.latencies["Cons"]) < 400:
            continue
        lat_array.append(sorted(block.latencies["Cons"])[int(400 * 99 / 100)])
        if len(generate_times) >= 2000:
            continue
        parents[block.hash] = block.parent
        refs[block.hash] = block.referees
        latency = int(max(block.latencies["Cons"]))
        generate_times[block.hash] = block.timestamp
        received_times[block.hash] = block.timestamp + latency
        difficulties[block.hash] = int(block.difficulty / 4)

    print("Lat avg", sum(lat_array) / len(lat_array),
          "block count", len(lat_array))
    compute_latency(aim_blocks, parents, refs, final_block, generate_times,
                    received_times, difficulties, lambda_n=4, risk=0.0001)
