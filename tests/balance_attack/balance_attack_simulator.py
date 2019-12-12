#!/usr/bin/env python3
import collections
import queue
import random
import multiprocessing
from statistics import mean
import time

class Parameters:

    def __init__(self):
        return


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

    def __init__(self, env, attack_params):
        self.env = env
        # Parameters checker
        for attr in ["num_nodes","average_block_period","evil_rate","latency","out_degree","termination_time"]:
            if not hasattr(self.env,  attr):
                print("{} unset".format(attr))
                exit()

        self.attack_params = attack_params
        self.message_queue = queue.PriorityQueue()

    def setup_chain(self):
        self.nodes = []
        for i in range(self.env.num_nodes):
            self.nodes.append(NodeLocalView(i))

        # Initialize adversary.
        self.debug_allow_borrow = self.env.debug_allow_borrow
        self.left_subtree_weight = 0
        self.right_subtree_weight = 0
        self.left_withheld_blocks_queue = queue.Queue()
        self.right_withheld_blocks_queue = queue.Queue()
        self.total_borrowed_blocks = 0
        self.left_borrowed_blocks = 0
        self.right_borrowed_blocks = 0
        self.withhold_done = False
        # The number of recent blocks mined under left side sent to the network.
        self.adv_left_recent_sent_blocks = collections.deque()
        self.adv_right_recent_sent_blocks = collections.deque()
        self.honest_left_recent_sent_blocks = collections.deque()
        self.honest_right_recent_sent_blocks = collections.deque()

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
            self.broadcast(0, i, "R", 0)
        self.honest_right_recent_sent_blocks.append((0, 0))
        self.right_subtree_weight += 1

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
                       < self.right_withheld_blocks_queue.qsize() + self.right_subtree_weight else\
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
                    self.honest_left_recent_sent_blocks.append((timestamp, block_id))
                else:
                    self.right_subtree_weight += 1
                    self.honest_right_recent_sent_blocks.append((timestamp, block_id))
                # Broadcast new blocks to neighbours
                self.broadcast(timestamp, miner, chirality, block_id)

            self.maintain_recent_blocks(timestamp)

            self.adversary_strategy(
                adversary_mined,
                self.left_subtree_weight - self.right_subtree_weight
                - len(self.honest_left_recent_sent_blocks) + len(self.honest_right_recent_sent_blocks),
                timestamp, [nodes_to_keep_left, nodes_to_keep_right],
                [self.left_withheld_blocks_queue, self.right_withheld_blocks_queue])
            block_id += 1

            self.process_network_events(timestamp)

            """
            print(f"local views after action:\n\tleft targets: %s,\n\tright targets: %s\n" % (
                repr([self.nodes[i] for i in targets[0]]),
                repr([self.nodes[i] for i in targets[1]]),
            ))
            """

            if self.is_chain_merged():
                print(f"Chain merged after {timestamp} seconds")
                return timestamp

        print(f"Chain unmerged after {self.env.termination_time} seconds... ")
        return self.env.termination_time

    def maintain_recent_blocks(self, timestamp):
        non_recent_timestamp = timestamp - self.attack_params["recent_timeout"]
        for recent_sent_blocks in [
            self.adv_left_recent_sent_blocks, self.adv_right_recent_sent_blocks,
            self.honest_left_recent_sent_blocks, self.honest_right_recent_sent_blocks,
        ]:
            while len(recent_sent_blocks) > 0 \
                and recent_sent_blocks[0][0] <= non_recent_timestamp:
                recent_sent_blocks.popleft()


    def adversary_send_withheld_block(self, chirality, target, timestamp):
        if chirality == "L":
            withheld_queue = self.left_withheld_blocks_queue
            recent_sent_blocks = self.adv_left_recent_sent_blocks
        else:
            withheld_queue = self.right_withheld_blocks_queue
            recent_sent_blocks = self.adv_right_recent_sent_blocks
        if withheld_queue.empty():
            if self.debug_allow_borrow:
                self.total_borrowed_blocks += 1
                if chirality == "L":
                    self.left_borrowed_blocks += 1
                else:
                    self.right_borrowed_blocks += 1
                blk = -self.total_borrowed_blocks
            else:
                return
        else:
            blk = withheld_queue.get()

        if chirality == "L":
            self.left_subtree_weight += 1
        else:
            self.right_subtree_weight += 1

        for node in target:
            self.message_queue.put((timestamp, node, chirality, blk))

        recent_sent_blocks.append((timestamp, blk))
        self.maintain_recent_blocks(timestamp)


    def adversary_strategy(self, adversary_mined, global_subtree_weight_diff, timestamp, targets, withhold_queues):
            if withhold_queues[0].qsize() + withhold_queues[1].qsize() >= self.attack_params["withhold"]:
                self.withhold_done = True

            adv_recent_sent_left = len(self.adv_left_recent_sent_blocks)
            adv_recent_sent_right = len(self.adv_right_recent_sent_blocks)
            approx_right_target_subtree_weight_diff = global_subtree_weight_diff - adv_recent_sent_left
            approx_left_target_subtree_weight_diff = global_subtree_weight_diff + adv_recent_sent_right
            extra_send = self.attack_params["extra_send"]
            left_send_count = -approx_left_target_subtree_weight_diff + extra_send
            right_send_count = approx_right_target_subtree_weight_diff + 1 + extra_send

            # Debug output only, estimation.
            """
            honest_recent_mined_left = len(self.honest_left_recent_sent_blocks)
            honest_recent_mined_right = len(self.honest_right_recent_sent_blocks)
            all_received_left = self.left_subtree_weight - adv_recent_sent_left - honest_recent_mined_left
            all_received_right = self.right_subtree_weight - adv_recent_sent_right - honest_recent_mined_right
            left_target_received_left = self.left_subtree_weight - honest_recent_mined_left
            right_target_received_right = self.right_subtree_weight - honest_recent_mined_right

            print(f"Global view before action: ({self.left_subtree_weight}, {self.right_subtree_weight}); "
                  f"Honest recent mined: ({honest_recent_mined_left}, {honest_recent_mined_right}), "
                  f"Adv recent sent: ({adv_recent_sent_left}, {adv_recent_sent_right}), "
                  f"Est. all received: ({all_received_left}, {all_received_right}), "
                  f"left received: ({left_target_received_left}, {all_received_right}), "
                  f"right received: ({all_received_left}, {right_target_received_right}); "
                  f"Adv to send: ({left_send_count}, {right_send_count}) in which extra_send {extra_send}, "
                  f"adv withhold: ({self.left_withheld_blocks_queue.qsize()}, {self.right_withheld_blocks_queue.qsize()}); "
                  f"adv borrowed blocks: ({self.left_borrowed_blocks}, {self.right_borrowed_blocks})."
            )
            """

            if (self.debug_allow_borrow or self.withhold_done) and left_send_count > 0:
                anti_chirality = "L"
                for i in range(left_send_count):
                    self.adversary_send_withheld_block(anti_chirality, targets[0], timestamp)

            if (self.debug_allow_borrow or self.withhold_done) and right_send_count > 0:
                anti_chirality = "R"
                for i in range(right_send_count):
                    self.adversary_send_withheld_block(anti_chirality, targets[1], timestamp)


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
    env.num_nodes = 100
    env.average_block_period = 0.25
    env.evil_rate = 0.218
    env.latency = 10
    env.out_degree = 99
    env.termination_time = 5400
    env.debug_allow_borrow = False

    return Simulator(env, {"withhold": 10, "recent_timeout": 10, "extra_send": 1}).main()

if __name__=="__main__":
    cpu_num = multiprocessing.cpu_count()
    repeats = 20
    p = multiprocessing.Pool(cpu_num)
    begin = time.time()
    attack_last_time = sorted(map(lambda x: x.get(), [p.apply_async(slave_simulator) for x in range(repeats)]))
    samples = 10
    print("len: %s" % len(attack_last_time))
    print(list(map(lambda percentile: attack_last_time[int((repeats - 1) * percentile / samples)], range(samples + 1))))
    end = time.time()
    print("Executed in {} seconds".format(end-begin))
