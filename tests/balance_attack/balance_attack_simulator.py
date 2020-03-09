#!/usr/bin/env python3
import collections
import queue
import random
import multiprocessing
from statistics import mean
import time
from strategy_fixed_peer_latency import StrategyFixedPeerLatency

class Parameters:
    def __init__(self):
        return

    def __repr__(self):
        return f"latency:{self.latency} num_nodes:{self.num_nodes} out_degree:{self.out_degree} withhold:{self.withhold}"

class NodeLocalView:
    def __init__(self, node_id):
        self.node_id = node_id
        self.left_subtree_weight = 0
        self.right_subtree_weight = 0
        self.received = set()
        self.update_chirality()

    def __repr__(self):
        return f"NodeWeight({self.left_subtree_weight}, {self.right_subtree_weight})"

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
    EVENT_BLOCK_DELIVER = "1. block_delivery_event"
    EVENT_MINE_BLOCK = "0. mine_block_event"
    EVENT_CHECK_MERGE = "3. test_check_merge"
    EVENT_ADV_RECEIVED_BLOCK = "2. adversary_received_honest_mined_block"
    EVENT_ADV_STRATEGY_TRIGGER = "5. run_adv_strategy"
    EVENT_QUEUE_EMPTY = "4. event_queue_empty"

    def __init__(self, env, attack_params):
        self.env = env
        self.adversary = StrategyFixedPeerLatency(
            env.debug_allow_borrow,
            attack_params["withhold"],
            attack_params["extra_send"],
            attack_params["one_way_latency"])
        # Parameters checker
        for attr in ["num_nodes","average_block_period","evil_rate","latency","out_degree","termination_time"]:
            if not hasattr(self.env, attr):
                print("{} unset".format(attr))
                exit()

        self.attack_params = attack_params
        self.event_queue = queue.PriorityQueue()

    def setup_chain(self):
        self.nodes = []
        for i in range(self.env.num_nodes):
            self.nodes.append(NodeLocalView(i))

    def setup_network(self):
        self.neighbors = [[]] * self.env.num_nodes
        self.neighbor_latencies = [[]] * self.env.num_nodes
        for i in range(self.env.num_nodes):
            peer_set = set(self.neighbors[i])
            peers = self.neighbors[i]
            latencies = self.neighbor_latencies[i]
            for j in range(self.env.out_degree - len(peer_set)):
                peer = random.randint(0, self.env.num_nodes-1)
                while peer in peer_set or peer == i:
                    peer = random.randint(0, self.env.num_nodes-1)
                latency = self.env.latency #*random.uniform(0.75,1.25)
                peer_set.add(peer)
                peers.append(peer)
                latencies.append(latency)
                self.neighbors[peer].append(i)
                self.neighbor_latencies[peer].append(latency)

        #print(self.neighbors)
    def run_test(self):
        # Initialize the target's tree
        nodes_to_keep_left = list(range(0, self.env.num_nodes, 2))
        nodes_to_keep_right = list(range(1, self.env.num_nodes, 2))

        for i in nodes_to_keep_left:
            self.nodes[i].chirality = "L"
        for i in nodes_to_keep_right:
            self.nodes[i].chirality = "R"
            self.nodes[i].deliver_block(0, "R")
            self.honest_node_broadcast_block(0, i, "R", 0)

        # FIXME: start up condition
        self.adversary.start_attack()

        # Executed the simulation
        block_id = 1
        timestamp = 0
        self.event_queue.put((0, Simulator.EVENT_MINE_BLOCK, None))
        while timestamp < self.env.termination_time:
            event_type, time, event = self.process_network_events()
            timestamp = time
            trigger_adversary_action = False

            if event_type == Simulator.EVENT_MINE_BLOCK:
                time_to_next_block = random.expovariate(1 / self.env.average_block_period)
                self.event_queue.put((time + time_to_next_block, Simulator.EVENT_MINE_BLOCK, None))

                adversary_mined = random.random() < self.env.evil_rate
                if adversary_mined:
                    print("MINED %s by adversary at %s" % (block_id, time))
                    #print("At %s, Adversary mined block %s" % (timestamp, block_id))
                    # Decide attack target
                    side = self.adversary.adversary_side_to_mine()
                    self.adversary.adversary_mined(side, block_id)
                    trigger_adversary_action = True
                else:
                    # Pick a number from 0 to num_nodes - 1 inclusive.
                    miner = random.randint(0, self.env.num_nodes-1)
                    #print("At %s, Miner %s mined block %s" % (timestamp, miner, block_id))
                    side = self.nodes[miner].chirality
                    print("MINED %s %s by node %s at %s" % (block_id, side, miner, time))
                    # Update attacker and miner's views
                    self.nodes[miner].deliver_block(block_id, side)
                    # Broadcast new blocks to neighbours
                    self.honest_node_broadcast_block(timestamp, miner, side, block_id)

                    self.event_queue.put((
                        time + self.attack_params["one_way_latency"],
                        Simulator.EVENT_ADV_RECEIVED_BLOCK,
                        (side, block_id)))
                    # Other miners receive this at timestamp + latency, attacker runs the strategy
                    # earlier so that adversary can deliver blocks before it (or right after it,
                    # it doesn't matter too much).
                    # TODO: for random latency, the adversary can only try to run its strategy more often.
                    self.event_queue.put((
                        time + self.env.latency - self.attack_params["one_way_latency"] - 0.01,
                        Simulator.EVENT_ADV_STRATEGY_TRIGGER,
                        None
                    ))
                block_id += 1

            elif event_type == Simulator.EVENT_CHECK_MERGE:
                #"""
                print(f"At {timestamp} local views after action:\n\tleft targets: %s,\n\tright targets: %s\n" % (
                    repr([self.nodes[i] for i in nodes_to_keep_left]),
                    repr([self.nodes[i] for i in nodes_to_keep_right]),
                ))
                #"""

                if self.is_chain_merged():
                    print(f"Chain merged after {timestamp} seconds")
                    return timestamp
            elif event_type == Simulator.EVENT_QUEUE_EMPTY:
                # Can't happen because of mining.
                pass
            elif event_type == Simulator.EVENT_ADV_RECEIVED_BLOCK:
                honest_mined_side, honest_mined_block = event
                self.adversary.honest_mined(
                    honest_mined_side, timestamp - self.attack_params["one_way_latency"], honest_mined_block)
                adversary_mined = False
            elif event_type == Simulator.EVENT_ADV_STRATEGY_TRIGGER:
                trigger_adversary_action = True

            if trigger_adversary_action:
                blocks_to_send = []
                debug_borrow_blocks_count, debug_borrow_blocks_withhold_queue = self.adversary.adversary_strategy(
                    adversary_mined,
                    timestamp,
                    self.attack_params["recent_timeout"],
                    blocks_to_send
                )
                if self.env.debug_allow_borrow:
                    for i in range(debug_borrow_blocks_count):
                        debug_borrow_blocks_withhold_queue.put(i - self.adversary.total_borrowed_blocks)
                    self.adversary.adversary_strategy(
                        adversary_mined,
                        timestamp,
                        self.attack_params["recent_timeout"],
                        blocks_to_send
                    )

                print(f"blocks_to_send {blocks_to_send}")
                time_delivery = timestamp + self.attack_params["one_way_latency"]
                for side, block in blocks_to_send:
                    if side == "L":
                        targets = nodes_to_keep_left
                    else:
                        targets = nodes_to_keep_right
                    for node in targets:
                        self.event_queue.put((time_delivery, Simulator.EVENT_BLOCK_DELIVER, (node, side, block)))
                self.event_queue.put((time_delivery, Simulator.EVENT_CHECK_MERGE, None))

        #print(f"Chain unmerged after {self.env.termination_time} seconds... ")
        return self.env.termination_time

    def is_chain_merged(self):
        side_per_node = list(map(
            lambda node: node.chirality,
            self.nodes
        ))
        return (not "L" in side_per_node) or (not "R" in side_per_node)


    def honest_node_broadcast_block(self, time, index, chirality, blk):
        peers = self.neighbors[index]
        for i in range(len(peers)):
            peer = peers[i]
            latency = self.neighbor_latencies[index][i]
            deliver_time = time + latency
            self.event_queue.put((deliver_time, Simulator.EVENT_BLOCK_DELIVER, (peer, chirality, blk)))


    def process_network_events(self, current_time = None):
        # Parse events and generate new ones in a BFS way
        while True:
            if self.event_queue.empty():
                return (Simulator.EVENT_QUEUE_EMPTY, self.env.termination_time, None)

            time, event_type, event = self.event_queue.get()

            if current_time is not None and time > current_time:
                self.event_queue.put((time, event_type, event))

            if event_type == Simulator.EVENT_BLOCK_DELIVER:
                index, chirality, blk = event
                if not blk in self.nodes[index].received:
                    self.nodes[index].deliver_block(blk, chirality)
                    self.honest_node_broadcast_block(time, index, chirality, blk)
            else:
                return (event_type, time, event)

    def main(self):
        self.setup_chain()
        self.setup_network()
        return self.run_test()



def slave_simulator(env):
    return Simulator(env, {
        "withhold": env.withhold,
        "recent_timeout": env.recent_timeout,
        "extra_send": 0,
        "one_way_latency": 0.1}).main()

if __name__=="__main__":
    cpu_num = multiprocessing.cpu_count()
    repeats = 10
    p = multiprocessing.Pool(cpu_num)

    for num_nodes in [16]:
        for latency in [10]:
            for out_degree in [5]:
                for withhold in [5]:
                    test_params = Parameters()
                    test_params.num_nodes = num_nodes
                    test_params.average_block_period = 0.25
                    test_params.evil_rate = 0.25
                    test_params.latency = latency
                    test_params.out_degree = out_degree
                    test_params.termination_time = 5400
                    test_params.debug_allow_borrow = False
                    #test_params.debug_allow_borrow = True
                    test_params.withhold = withhold
                    test_params.recent_timeout = 10
                    print(test_params)
                    begin = time.time()
                    attack_last_time = sorted(p.map(slave_simulator, [test_params] * repeats))
                    samples = 10
                    print(list(map(lambda percentile: attack_last_time[int((repeats - 1) * percentile / samples)], range(samples + 1))))
                    end = time.time()
                    print("Executed in %.2f seconds" % (end - begin))