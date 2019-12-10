#!/usr/bin/env python3
import queue
import random
import multiprocessing
from statistics import mean
import time

class Parameters:

    def __init__(self):
        return


class NodeLocalView:

    def __init__(self,num_nodes):
        self.left_subtree_weight = 0
        self.right_subtree_weight = 0
        self.received = set()
        self.update_chirality()

    def deliver_block(self, block_id, chirality):
        self.received.add(block_id)
        # Update the subtree weight
        if chirality == "L":
            self.left_subtree_weight += 1
        else:
            self.right_subtree_weight += 1
        self.update_chirality()

    def update_chirality(self):
        if self.left_subtree_weight >= self.right_subtree_weight:
            self.chirality = "L"
        else:
            self.chirality = "R"


class Simulator:

    def __init__(self, env, threshold):
        self.env = env
        # Parameters checker
        for attr in ["num_nodes","average_block_period","evil_rate","latency","out_degree","termination_time"]:
            if not hasattr(self.env,  attr):
                print("{} unset".format(attr))
                exit()

        self.threshold = threshold
        self.message_queue = queue.PriorityQueue()

    def setup_chain(self):
        self.nodes = []
        for i in range(self.env.num_nodes):
            self.nodes.append(NodeLocalView(self.env.num_nodes))
        self.left_subtree_weight = 0
        self.right_subtree_weight = 0
        self.left_withheld_blocks_queue = queue.Queue()
        self.right_withheld_blocks_queue = queue.Queue()

    def setup_network(self):
        self.neighbors = []
        self.neighbor_latencies = []
        for i in range(self.env.num_nodes):
            peers = set()
            latencies = []
            for j in range(self.env.out_degree):
                peer = random.randint(0, self.env.num_nodes-1)
                while peer in peers or peer == i:
                    peer = random.randint(0, self.env.num_nodes-1)
                peers.add(peer)
                latencies.append(self.env.latency)
            self.neighbors.append(list(peers))
            self.neighbor_latencies.append(latencies)

    def run_test(self):


        # Initialize the target's tree
        nodes_to_keep_left = list(range(0, self.env.num_nodes, 2))
        nodes_to_keep_right = list(range(1, self.env.num_nodes, 2))

        for i in nodes_to_keep_left:
            self.nodes[i].chirality = "L"
        for i in nodes_to_keep_right:
            self.nodes[i].chirality = "R"
            self.nodes[i].deliver_block(0, "R")

        # Executed the simulation
        block_id = 1
        timestamp = 0
        while timestamp < self.env.termination_time:
            timestamp += random.expovariate(1 / self.env.average_block_period)
            self.process_network_events(timestamp)

            adversary_mined = random.random() < self.env.evil_rate
            if adversary_mined:
                #print("At %s, Adversary mined block %s" % (timestamp, block_id))
                # Decide attack target
                withhold_queue, chirality, target = (self.left_withheld_blocks_queue, "L", nodes_to_keep_left) \
                    if self.left_withheld_blocks_queue.qsize() + self.left_subtree_weight \
                       <= self.right_withheld_blocks_queue.qsize() + self.right_subtree_weight else\
                    (self.right_withheld_blocks_queue, "R", nodes_to_keep_right)
                withhold_queue.put(block_id)
            else:
                # Pick a number from 0 to num_nodes - 1 inclusive.
                miner = random.randint(0, self.env.num_nodes-1)
                #print("At %s, Miner %s mined block %s" % (timestamp, miner, block_id))
                chirality = self.nodes[miner].chirality
                # Update attacker and miner's views
                self.nodes[miner].deliver_block(block_id, chirality)
                if chirality == "L":
                    self.left_subtree_weight += 1
                else:
                    self.right_subtree_weight += 1
                # Broadcast new blocks to neighbours
                self.broadcast(timestamp, miner, chirality, block_id)

            self.adversary_strategy(
                adversary_mined, self.left_subtree_weight - self.right_subtree_weight,
                timestamp, [nodes_to_keep_left, nodes_to_keep_right],
                [self.left_withheld_blocks_queue, self.right_withheld_blocks_queue])
            block_id += 1

            if self.is_chain_merged():
                print("Chain merged after {} seconds".format(timestamp))
                return timestamp

        print("Chain unmerged after {} seconds... ".format(self.env.termination_time))
        return self.env.termination_time

    def adversary_strategy(self, adversary_mined, global_subtree_weight_diff, timestamp, targets, withhold_queues):
        if adversary_mined:
            if global_subtree_weight_diff >= 0:
                anti_chirality = "R"
                target = targets[1]
                withhold_queue = withhold_queues[1]
            else:
                anti_chirality = "L"
                target = targets[0]
                withhold_queue = withhold_queues[0]
            send_count = abs(global_subtree_weight_diff)
            if send_count >= self.threshold:
                for i in range(send_count):
                    if withhold_queue.empty():
                        break
                    blk = withhold_queue.get()
                    if anti_chirality == "L":
                        self.left_subtree_weight += 1
                    else:
                        self.right_subtree_weight += 1
                    for j in target:
                        self.message_queue.put((timestamp, j, anti_chirality, blk))


    def is_chain_merged(self):
        side_per_node = list(map(
            lambda node: node.chirality,
            self.nodes
        ))
        return (not "L" in side_per_node) or (not "R" in side_per_node)


    def broadcast(self, time, index, chirality, blk):
        peers = self.neighbors[index]
        for i in range(len(peers)):
            peer = peers[i]
            latency = self.neighbor_latencies[index][i]
            deliver_time = time + latency
            self.message_queue.put((deliver_time, peer, chirality, blk))


    def process_network_events(self, current_stamp):
        # Parse events and generate new ones in a BFS way
        while True:
            # Safely get valid event from history
            if self.message_queue.empty():
                return
            stamp, index, chirality, blk = self.message_queue.get()
            if stamp > current_stamp:
                self.message_queue.put((stamp, index, chirality, blk))
                return

            # Only new blocks will modify the memory
            if not blk in self.nodes[index].received:
                self.nodes[index].deliver_block(blk, chirality)
                self.broadcast(stamp, index, chirality, blk)

    def main(self):
        self.setup_chain()
        self.setup_network()
        return self.run_test()



def slave_simulator():
    env = Parameters()
    env.num_nodes = 6
    env.average_block_period = 0.25
    env.evil_rate = 0.2
    env.latency = 10
    env.out_degree = 5
    env.termination_time = 20000

    return Simulator(env,3).main()

if __name__=="__main__":
    cpu_num = multiprocessing.cpu_count()
    repeats = 100
    p = multiprocessing.Pool(cpu_num)
    begin = time.time()
    attack_last_time = sorted(map(lambda x: x.get(), [p.apply_async(slave_simulator) for x in range(repeats)]))
    samples = 10
    print("len: %s" % len(attack_last_time))
    print(list(map(lambda percentile: attack_last_time[int((repeats - 1) * percentile / samples)], range(samples + 1))))
    end = time.time()
    print("Executed in {} seconds".format(end-begin))
