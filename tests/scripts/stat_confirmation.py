#!/usr/bin/env python3

from stat_latency_map_reduce import LogAggregator, BlockLatencyType, Percentile, parse_value, Statistics
from stat_latency import Table
import pickle
import sys
from queue import Queue
import os
import math

def accept(t, lambda_n, sib_tree_size, max_n, r):
    if t < 0:
        return False
    n_m = max_n - sib_tree_size
    q = 0.1
    s = 1.0
    for k in range(n_m + 1):
        a = math.exp(-1 * q * lambda_n * t)
        b = 1.0
        for j in range(1, k + 1):
            b *= q * lambda_n * t
            b /= j
        # b = math.pow(q * lambda_n * t, k)
        # c = math.factorial(k)
        d = max(1 - math.pow(0.11, n_m - k + 1) * 14, 0)
        s -= b * a * d
        if s < r:
            print("risk", max_n, s)
            return True
    # print("risk", n_m, s)
    return False


def treeSize(t, node, subtree):
    return len(subtree[node])


def compute_latency(parents, refs, final_block, g_time, r_time, lambda_n=4, risk=0.0001, adversary_power=0.2):
    r = risk
    # q = adversary_power / (1 - adversary_power)
    final_block = None

    chain = []
    index = final_block
    while index in parents:
        chain.append(index)
        index = parents[index]
    chain.reverse()
    childs = {}
    des = {}
    for i in parents:
        p = parents[i]
        if p in childs:
            childs[p].append(i)
        else:
            childs[p] = [i]
        if p in des:
            des[p].append(i)
        else:
            des[p] = [i]
    for i in refs:
        for p in refs[i]:
            if p in des:
                des[p].append(i)
            else:
                des[p] = [i]
    subtree = {}
    for start in g_time:
        queue = Queue()
        queue.put(start)
        accessed = {}
        subtree[start] = []
        while not queue.empty():
            b = queue.get()
            if b in accessed:
                continue
            if b in childs:
                for c in childs[b]:
                    queue.put(c)
            accessed[b] = True
            if b != start:
                subtree[start].append(b)
    future = {}
    for start in g_time:
        queue = Queue()
        queue.put(start)
        accessed = {}
        future[start] = []
        while not queue.empty():
            b = queue.get()
            if b in accessed:
                continue
            if b in des:
                for c in des[b]:
                    queue.put(c)
            accessed[b] = True
            if b != start:
                future[start].append(b)
    c_time = {}
    for b in g_time:
        if b not in parents:
            print("skip not in parents", b)
            continue
        if parents[b] not in r_time:
            print("skip not in r_time", parents[b])
            continue
        received_time = sorted([r_time[_] for _ in subtree[b] if _ in r_time])
        siblings = [_ for _ in childs[parents[b]] if _ != b]
        for j in range(len(received_time)):
            r_t = received_time[j]
            sib_tree_size = 0
            if len(siblings) != 0:
                sib_tree_size = max([treeSize(r_t, sib, subtree)
                                     for sib in siblings])
            if accept((r_t - r_time[parents[b]]), lambda_n, sib_tree_size, j + 1, r):
                c_time[b] = r_t
                break
    final_c_time = {}
    for b in g_time:
        if b in c_time:
            final_c_time[b] = c_time[b]
        if b in future:
            f_commit = [c_time[_] for _ in future[b] if _ in c_time]
            if len(f_commit) == 0:
                continue
            else:
                final_c_time[b] = min(f_commit)
    for b in final_c_time:
        if b in future:
            for f in future[b]:
                if f in final_c_time and final_c_time[f] < final_c_time[b]:
                    final_c_time[f] = final_c_time[b]
    lat = []
    for b in final_c_time:
        lat.append((final_c_time[b] - g_time[b]))
    lat_s = sorted(lat)
    print("Latency from block number: ", len(lat_s))
    print("%.2f\t%.2f\t%.2f\t%.2f\t%.2f" % (lat_s[0], lat_s[int(len(
        lat_s) * 0.25)], sum(lat_s) / len(lat_s), lat_s[int(len(lat_s) * 0.75)], lat_s[-1]))
    return lat_s

def find_best_block(logs_dir:str):
    full_path = os.path.abspath(logs_dir)
    log_path = os.path.join(os.path.dirname(full_path), "exp.log")
    if not os.path.exists(log_path):
        log_path = os.path.join(full_path, "exp.log")
        if not os.path.exists(log_path):
            print("cannot find the log file exp.log")
            sys.exit(2)

    with open(log_path, "r", encoding='UTF-8') as file:
        for line in file.readlines():
            if "Best block: " in line:
                h = parse_value(line, "Best block: ", None)[:-1]
                print("best block:", h)
                return h

    print("cannot find the best block in log file.")
    sys.exit(3)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Parameter required: <logs_dir> <lambda_n> [<best_block>]")
        sys.exit(1)

    logs_dir = sys.argv[1]
    lambda_n = 1/float(sys.argv[2])
    best_block = sys.argv[3] if len(sys.argv) >= 4 else find_best_block(logs_dir)

    print("Loading logs ...")
    agg = LogAggregator.load(logs_dir)
    parents = {}
    refs = {}
    generate_times = {}
    received_times_max = {}
    received_times_p99 = {}

    for block in agg.blocks.values():
        parents[block.hash] = block.parent
        refs[block.hash] = block.referees
        generate_times[block.hash] = block.timestamp
        latencies_stat = Statistics(block.get_latencies(BlockLatencyType.Cons))
        received_times_max[block.hash] = block.timestamp + latencies_stat.get(Percentile.Max)
        received_times_p99[block.hash] = block.timestamp + latencies_stat.get(Percentile.P99)

    #print("computing with broadcast latency (Max) ...")
    #latencies_max = compute_latency(parents, refs, best_block, generate_times, received_times_max, lambda_n)
    print("computing with broadcast latency (P99) ...")
    latencies_p99 = compute_latency(parents, refs, best_block, generate_times, received_times_p99, lambda_n)

    table = Table.new_matrix("confirmation latency")
    #table.add_data("Max", "%.2f", latencies_max)
    table.add_data("P99", "%.2f", latencies_p99)
    table.pretty_print()