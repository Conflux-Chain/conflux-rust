import collections
import queue

class StrategyFixedPeerLatency:
    def __init__(self, debug_allow_borrow, withhold, extra_send, one_way_latency):
        # Config fields
        self.debug_allow_borrow = debug_allow_borrow
        self.withhold = withhold
        self.extra_send = extra_send
        # The one way latency between adversary and honest nodes.
        self.one_way_latency = one_way_latency
        self.initialize_attack()

    def initialize_attack(self):
        # State fields.
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
        self.honest_left_recent_mined_blocks = collections.deque()
        self.honest_right_recent_mined_blocks = collections.deque()

    def start_attack(self):
        # FIXME: determine the initial condition for the real world attack.
        self.adv_right_recent_sent_blocks.append((0, 0))
        self.right_subtree_weight += 1

    def adversary_side_to_mine(self):
        return "L" if self.left_withheld_blocks_queue.qsize() + self.left_subtree_weight \
            < self.right_withheld_blocks_queue.qsize() + self.right_subtree_weight else \
        "R"

    def adversary_mined(self, side, block):
        if side == "L":
            withhold_queue = self.left_withheld_blocks_queue
        else:
            withhold_queue = self.right_withheld_blocks_queue
        withhold_queue.put(block)

    def honest_mined(self, side, time_mined, block):
        if side == "L":
            self.left_subtree_weight += 1
            self.honest_left_recent_mined_blocks.append((time_mined, block))
        else:
            self.right_subtree_weight += 1
            self.honest_right_recent_mined_blocks.append((time_mined, block))

    def maintain_recent_blocks(self, timestamp, recent_latency):
        non_recent_timestamp = timestamp - recent_latency + self.one_way_latency
        for recent_sent_blocks in [
            self.adv_left_recent_sent_blocks, self.adv_right_recent_sent_blocks,
            self.honest_left_recent_mined_blocks, self.honest_right_recent_mined_blocks,
        ]:
            while len(recent_sent_blocks) > 0 \
                    and recent_sent_blocks[0][0] <= non_recent_timestamp:
                recent_sent_blocks.popleft()

    def count_later_items(deque, timestamp):
        count = 0
        i = len(deque) - 1
        while i >= 0:
            if deque[i][0] > timestamp:
                count += 1
                i -= 1
            else:
                break
        return count

    def adversary_strategy(self, adversary_mined, timestamp, recent_latency, blocks_to_send):
        # When adversary run the strategy too close to its previous run, the released
        # withheld blocks are not delivered to the honest miners yet, thus the adversary
        # must take into consideration of the effect of the previously sent blocks.
        #
        # Consider the extreme case: what if the strategy is triggered twice each time.
        # The latter run should not send out any blocks.

        self.maintain_recent_blocks(timestamp, recent_latency)

        honest_recent_mined_left = len(self.honest_left_recent_mined_blocks)
        honest_recent_mined_right = len(self.honest_right_recent_mined_blocks)

        in_flight_adv_left_sent_blocks = StrategyFixedPeerLatency.count_later_items(
            self.adv_left_recent_sent_blocks, timestamp - self.one_way_latency)
        in_flight_adv_right_sent_blocks = StrategyFixedPeerLatency.count_later_items(
            self.adv_right_recent_sent_blocks, timestamp - self.one_way_latency)

        global_subtree_weight_diff = self.left_subtree_weight - self.right_subtree_weight \
            - honest_recent_mined_left + honest_recent_mined_right \
            - in_flight_adv_left_sent_blocks + in_flight_adv_right_sent_blocks

        if self.left_withheld_blocks_queue.qsize() + self.right_withheld_blocks_queue.qsize() >= self.withhold:
            self.withhold_done = True

        adv_recent_sent_left = len(self.adv_left_recent_sent_blocks)
        adv_recent_sent_right = len(self.adv_right_recent_sent_blocks)
        adv_recent_delivery_left = adv_recent_sent_left - in_flight_adv_left_sent_blocks
        adv_recent_delivery_right = adv_recent_sent_right - in_flight_adv_right_sent_blocks
        approx_right_target_subtree_weight_diff = global_subtree_weight_diff - adv_recent_delivery_left
        approx_left_target_subtree_weight_diff = global_subtree_weight_diff + adv_recent_delivery_right
        extra_send = self.extra_send
        left_send_count = -approx_left_target_subtree_weight_diff + extra_send
        right_send_count = approx_right_target_subtree_weight_diff + 1 + extra_send
        actual_left_send = left_send_count - in_flight_adv_left_sent_blocks
        actual_right_send = right_send_count - in_flight_adv_right_sent_blocks


        # Debug output only, estimation.
        all_received_left = self.left_subtree_weight - adv_recent_sent_left - honest_recent_mined_left
        all_received_right = self.right_subtree_weight - adv_recent_sent_right - honest_recent_mined_right
        left_target_received_left = self.left_subtree_weight - in_flight_adv_left_sent_blocks - honest_recent_mined_left
        right_target_received_right = self.right_subtree_weight - in_flight_adv_right_sent_blocks - honest_recent_mined_right

        #"""
        print(f"At {timestamp} global_subtree_weight_diff: {global_subtree_weight_diff} "
              f"Global view before action: ({self.left_subtree_weight}, {self.right_subtree_weight}); "
              f"Honest recent mined: ({honest_recent_mined_left}, {honest_recent_mined_right}), "
              f"Adv sent recent delivered: ({adv_recent_delivery_left}, {adv_recent_delivery_right}), "
              f"Adv in flight sent: ({in_flight_adv_left_sent_blocks}, {in_flight_adv_right_sent_blocks}), "
              f"Est. all received: ({all_received_left}, {all_received_right}), "
              f"left received: ({left_target_received_left}, {all_received_right}), "
              f"right received: ({all_received_left}, {right_target_received_right}); "
              f"Adv to send: ({left_send_count}, {right_send_count}) in which extra_send {extra_send}, "
              f"Adv actual to send: ({actual_left_send}, {actual_right_send}), "
              f"adv withhold: ({self.left_withheld_blocks_queue.qsize()}, {self.right_withheld_blocks_queue.qsize()}); "
              f"adv borrowed blocks: ({self.left_borrowed_blocks}, {self.right_borrowed_blocks})."
              )
        #"""

        debug_borrow_blocks_count = 0
        debug_borrow_blocks_withhold_queue = None
        if self.debug_allow_borrow or self.withhold_done:
            if actual_left_send > 0:
                for i in range(left_send_count):
                    debug_borrow_blocks_count += \
                        self.pop_withheld_block_to_send("L", timestamp, blocks_to_send)
                    debug_borrow_blocks_withhold_queue = self.left_withheld_blocks_queue
            if actual_right_send > 0:
                for i in range(right_send_count):
                    debug_borrow_blocks_count += \
                        self.pop_withheld_block_to_send("R", timestamp, blocks_to_send)
                    debug_borrow_blocks_withhold_queue = self.right_withheld_blocks_queue
        return (debug_borrow_blocks_count, debug_borrow_blocks_withhold_queue)

    def pop_withheld_block_to_send(self, side, timestamp, blocks_to_send):
        if side == "L":
            withheld_queue = self.left_withheld_blocks_queue
            recent_delivered_blocks = self.adv_left_recent_sent_blocks
        else:
            withheld_queue = self.right_withheld_blocks_queue
            recent_delivered_blocks = self.adv_right_recent_sent_blocks
        if withheld_queue.empty():
            if self.debug_allow_borrow:
                self.total_borrowed_blocks += 1
                if side == "L":
                    self.left_borrowed_blocks += 1
                else:
                    self.right_borrowed_blocks += 1
                return 1
            else:
                return 0
        else:
            blk = withheld_queue.get()

        if side == "L":
            self.left_subtree_weight += 1
        else:
            self.right_subtree_weight += 1

        recent_delivered_blocks.append((timestamp + self.one_way_latency, blk))
        blocks_to_send.append((side, blk))
        return 0
