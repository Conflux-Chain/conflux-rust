#!/usr/bin/env python3

import csv
import os
import sys
import dateutil.parser
import time
from concurrent.futures import ThreadPoolExecutor
from prettytable import PrettyTable
from stat_latency_map_reduce import BlockLatencyType, Percentile, Statistics, HostLogReducer, LogAggregator

class Table:
    def __init__(self, header:list):
        self.header = header
        self.rows = []

    def add_row(self, row:list):
        assert len(row) == len(self.header), "row and header length mismatch"
        self.rows.append(row)

    def pretty_print(self):
        table = PrettyTable()
        table.field_names = self.header

        for row in self.rows:
            table.add_row(row)

        print(table)

    def output_csv(self, output_file:str):
        with open(output_file, "w", newline='') as fp:
            writer = csv.writer(fp)
            writer.writerow(self.header)
            for row in self.rows:
                writer.writerow(row)

    @staticmethod
    def new_matrix(name:str):
        header = [name]

        for p in Percentile:
            if p is not Percentile.Min:
                header.append(p.name)

        return Table(header)

    def add_data(self, name:str, data_format:str, data:list):
        self.add_stat(name, data_format, Statistics(data))

    def add_stat(self, name:str, data_format:str, stat:Statistics):
        row = [name]

        for p in Percentile:
            if p is Percentile.Avg:
                row.append(stat.get(p))
            elif p is not Percentile.Min:
                row.append(stat.get(p, data_format))

        self.add_row(row)

class LogAnalyzer:
    def __init__(self, stat_name:str, log_dir:str, csv_output:str):
        self.stat_name = stat_name
        self.log_dir = log_dir
        self.csv_output = csv_output

    def analyze(self):
        self.agg = LogAggregator.load(self.log_dir)

        print("{} nodes in total".format(len(self.agg.sync_cons_gap_stats)))
        print("{} blocks generated".format(len(self.agg.blocks)))

        self.agg.validate()
        self.agg.generate_latency_stat()

        table = Table.new_matrix(self.stat_name)

        for t in BlockLatencyType:
            for p in Percentile:
                name = "block broadcast latency ({}/{})".format(t.name, p.name)
                table.add_stat(name, "%.2f", self.agg.stat_block_latency(t, p))
        for p in Percentile:
            name = "tx broadcast latency ({})".format(p.name)
            table.add_stat(name, "%.2f", self.agg.stat_tx_latency(p))
        for p in Percentile:
            name_tx_packed_to_block ="tx packed to block latency ({})".format(p.name)
            table.add_stat(name_tx_packed_to_block, "%.2f", self.agg.stat_tx_packed_to_block_latency(p))
        table.add_stat("min tx packed to block latency", "%.2f", self.agg.stat_min_tx_packed_to_block_latency())
        table.add_stat("by_block_ratio", "%.2f", self.agg.stat_tx_ratio())

        block_txs_list = []
        block_size_list = []
        block_timestamp_list = []
        referee_count_list = []
        max_time = 0
        min_time = 10 ** 40
        for block in self.agg.blocks.values():
            block_txs_list.append(block.txs)
            block_size_list.append(block.size)
            block_timestamp_list.append(block.timestamp)
            referee_count_list.append(len(block.referees))
            # Ignore the empty warm-up blocks at the start
            if block.txs > 0:
                ts = block.timestamp
                if ts < min_time:
                    min_time = ts
                if ts > max_time:
                    max_time = ts

        table.add_data("block txs", "%d", block_txs_list)
        table.add_data("block size", "%d", block_size_list)
        table.add_data("block referees", "%d", referee_count_list)

        block_timestamp_list.sort()
        intervals = []
        for i in range(1, len(block_timestamp_list)):
            intervals.append(block_timestamp_list[i] - block_timestamp_list[i-1])
        table.add_data("block generation interval", "%.2f", intervals)

        for p in [Percentile.Avg, Percentile.P50, Percentile.P90, Percentile.P99, Percentile.Max]:
            name = "node sync/cons gap ({})".format(p.name)
            if p is Percentile.Avg:
                table.add_stat(name, None, self.agg.stat_sync_cons_gap(p))
            else:
                table.add_stat(name, "%d", self.agg.stat_sync_cons_gap(p))

        tx_sum = sum(block_txs_list)
        print("{} txs generated".format(tx_sum))
        print("Throughput is {}".format(tx_sum / (max_time - min_time)))
        table.pretty_print()
        if self.csv_output is not None:
            table.output_csv(self.csv_output)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Parameter required: <stat_name> <log_dir> [<csv_output>]")
        sys.exit(1)

    csv_output = None if len(sys.argv) == 3 else sys.argv[3]

    LogAnalyzer(sys.argv[1], sys.argv[2], csv_output).analyze()