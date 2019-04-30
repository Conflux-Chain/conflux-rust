#!/usr/bin/env python3

import os
import sys
import dateutil.parser
import json
import enum
from concurrent.futures import ThreadPoolExecutor

def parse_value(log_line:str, prefix:str, suffix:str):
    start = 0 if prefix is None else log_line.index(prefix) + len(prefix)
    end = len(log_line) if suffix is None else log_line.index(suffix, start)
    return log_line[start:end]

def parse_log_timestamp(log_line:str):
    prefix = None if log_line.find("/conflux.log:") == -1 else "/conflux.log:"
    log_time = parse_value(log_line, prefix, " ")
    return round(dateutil.parser.parse(log_time).timestamp(), 2)

class BlockLatencyType(enum.Enum):
    Sync = 0
    Cons = 1

class Block:
    def __init__(self, hash:str, parent_hash:str, timestamp:float, height:int, referees:list):
        self.hash = hash
        self.parent = parent_hash
        self.timestamp = timestamp
        self.height = height
        self.referees = referees

        self.txs = 0
        self.size = 0

        # [latency_type, latency]
        self.latencies = {}
        for t in BlockLatencyType:
            self.latencies[t.name] = []

    @staticmethod
    def __parse_block_header__(log_line:str):
        parent_hash = parse_value(log_line, "parent_hash: ", ",")
        height = int(parse_value(log_line, "height: ", ","))
        timestamp = int(parse_value(log_line, "timestamp: ", ","))
        block_hash = parse_value(log_line, "hash: Some(", ")")
        assert len(block_hash) == 66, "invalid block hash length, line = {}".format(log_line)
        referees = []
        for ref_hash in parse_value(log_line, "referee_hashes: [", "]").split(","):
            ref_hash = ref_hash.strip()
            if len(ref_hash) > 0:
                assert len(ref_hash) == 66, "invalid block referee hash length, line = {}".format(log_line)
                referees.append(ref_hash)
        return Block(block_hash, parent_hash, timestamp, height, referees)

    @staticmethod
    def receive(log_line:str, latency_type:BlockLatencyType):
        log_timestamp = parse_log_timestamp(log_line)
        block = Block.__parse_block_header__(log_line)
        block.txs = int(parse_value(log_line, "tx_count=", ","))
        block.size = int(parse_value(log_line, "block_size=", None))
        block.latencies[latency_type.name].append(round(log_timestamp - block.timestamp, 2))
        return block

    @staticmethod
    def add_or_merge(blocks:dict, block):
        if blocks.get(block.hash) is None:
            blocks[block.hash] = block
        else:
            blocks[block.hash].merge(block)

    def merge(self, another):
        if self.hash != another.hash:
            return

        if self.size == 0 and another.size > 0:
            self.size = another.size

        for t in BlockLatencyType:
            self.latencies[t.name].extend(another.latencies[t.name])

    def latency_count(self, t:BlockLatencyType):
        return len(self.latencies[t.name])

    def get_latencies(self, t:BlockLatencyType):
        return self.latencies[t.name]

class Percentile(enum.Enum):
    Min = 0
    Avg = "avg"
    P50 = 0.5
    P80 = 0.8
    P90 = 0.9
    P95 = 0.95
    P99 = 0.99
    P999 = 0.999
    Max = 1

class Statistics:
    def __init__(self, data:list, avg_ndigits=2, sort=True):
        if data is None or len(data) == 0:
            return

        if sort:
            data.sort()

        data_len = len(data)

        for p in Percentile:
            if p is Percentile.Avg:
                value = sum(data) / data_len
                if avg_ndigits is not None:
                    value = round(value, avg_ndigits)
            else:
                value = data[int((data_len - 1) * p.value)]

            self.__dict__[p.name] = value

    def get(self, p:Percentile, data_format:str=None):
        result = self.__dict__[p.name]

        if data_format is not None:
            result = data_format % result

        return result

class NodeLogMapper:
    def __init__(self, log_file:str):
        assert os.path.exists(log_file), "log file not found: {}".format(log_file)
        self.log_file = log_file

        self.blocks = {}
        self.sync_cons_gaps = []

    @staticmethod
    def mapf(log_file:str):
        mapper = NodeLogMapper(log_file)
        mapper.map()
        return mapper

    def map(self):
        with open(self.log_file, "r", encoding='UTF-8') as file:
            for line in file.readlines():
                self.parse_log_line(line)

    def parse_log_line(self, line:str):
        if "new block inserted into graph" in line:
            block = Block.receive(line, BlockLatencyType.Sync)
            Block.add_or_merge(self.blocks, block)

        if "insert new block into consensus" in line:
            block = Block.receive(line, BlockLatencyType.Cons)
            Block.add_or_merge(self.blocks, block)

        if "Statistics" in line:
            sync_len = int(parse_value(line, "SyncGraphStatistics { inserted_block_count: ", " }"))
            cons_len = int(parse_value(line, "ConsensusGraphStatistics { inserted_block_count: ", " }"))
            assert sync_len >= cons_len, "invalid statistics for sync/cons gap, log line = {}".format(line)
            self.sync_cons_gaps.append(sync_len - cons_len)

class HostLogReducer:
    def __init__(self, node_mappers:list):
        self.node_mappers = node_mappers

        self.blocks = {}
        self.sync_cons_gap_stats = []

    def reduce(self):
        for mapper in self.node_mappers:
            self.sync_cons_gap_stats.append(Statistics(mapper.sync_cons_gaps))

            for b in mapper.blocks.values():
                Block.add_or_merge(self.blocks, b)

    def dump(self, output_file:str):
        data = {
            "blocks": self.blocks,
            "sync_cons_gap_stats": self.sync_cons_gap_stats,
        }

        with open(output_file, "w") as fp:
            json.dump(data, fp, default=lambda o: o.__dict__)

    def dumps(self):
        data = {
            "blocks": self.blocks,
            "sync_cons_gap_stats": self.sync_cons_gap_stats,
        }

        return json.dumps(data, default=lambda o: o.__dict__)

    @staticmethod
    def load(data:dict):
        reducer = HostLogReducer(None)

        for stat_dict in data["sync_cons_gap_stats"]:
            stat = Statistics([1])
            stat.__dict__ = stat_dict
            reducer.sync_cons_gap_stats.append(stat)

        for block_dict in data["blocks"].values():
            block = Block("", "", 0, 0, [])
            block.__dict__ = block_dict
            reducer.blocks[block.hash] = block

        return reducer

    @staticmethod
    def loadf(input_file:str):
        with open(input_file, "r") as fp:
            data = json.load(fp)
            return HostLogReducer.load(data)

    @staticmethod
    def reduced(log_dir:str, executor:ThreadPoolExecutor):
        futures = []
        for (path, _, files) in os.walk(log_dir):
            for f in files:
                if f == "conflux.log":
                    log_file = os.path.join(path, f)
                    futures.append(executor.submit(NodeLogMapper.mapf, log_file))

        mappers = []
        for f in futures:
            mappers.append(f.result())

        # reduce logs for host
        reducer = HostLogReducer(mappers)
        reducer.reduce()
        return reducer


class LogAggregator:
    def __init__(self):
        self.blocks = {}
        self.sync_cons_gap_stats = []

        # [latency_type, [block_hash, latency_stat]]
        self.block_latency_stats = {}
        for t in BlockLatencyType:
            self.block_latency_stats[t.name] = {}

    def add_host(self, host_log:HostLogReducer):
        self.sync_cons_gap_stats.extend(host_log.sync_cons_gap_stats)

        for b in host_log.blocks.values():
            Block.add_or_merge(self.blocks, b)

    def validate(self):
        num_nodes = len(self.sync_cons_gap_stats)

        for b in self.blocks.values():
            count_sync = b.latency_count(BlockLatencyType.Sync)
            if count_sync != num_nodes:
                print("sync graph missed block {}: received = {}, total = {}".format(b.hash, count_sync, num_nodes))

    def stat_sync_cons_gap(self, p:Percentile):
        data = []

        for stat in self.sync_cons_gap_stats:
            data.append(stat.get(p))

        return Statistics(data)

    def generate_latency_stat(self):
        for b in self.blocks.values():
            for t in BlockLatencyType:
                self.block_latency_stats[t.name][b.hash] = Statistics(b.get_latencies(t))

    def stat_latency(self, t:BlockLatencyType, p:Percentile):
        data = []

        for block_stat in self.block_latency_stats[t.name].values():
            data.append(block_stat.get(p))

        return Statistics(data)

    @staticmethod
    def load(logs_dir):
        agg = LogAggregator()
        executor = ThreadPoolExecutor(max_workers=8)

        futures = []
        for (path, _, files) in os.walk(logs_dir):
            for f in files:
                if f == "blocks.log":
                    log_file = os.path.join(path, f)
                    futures.append(executor.submit(HostLogReducer.loadf, log_file))

        for f in futures:
            agg.add_host(f.result())

        agg.validate()
        agg.generate_latency_stat()

        executor.shutdown()

        return agg

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Parameter required: <log_dir> <output_file>")
        sys.exit(1)

    log_dir = sys.argv[1]
    output_file = sys.argv[2]

    executor = ThreadPoolExecutor()
    reducer = HostLogReducer.reduced(log_dir, executor)
    reducer.dump(output_file)
    executor.shutdown()