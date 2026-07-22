#!/usr/bin/env python3
"""
Regression test for the network-layer simultaneous-dial bug.

When two nodes simultaneously dial each other, each side's
`SessionManager::update_ingress_node_id` sees the incoming ingress as a
duplicate of its own outbound and unconditionally replaces the index
entry, causing `kill_connection_by_token` to kill the egress and log
"Remove old session from the same node". With the bug, both sides do
this, so both TCP connections die.

After the fix, the network layer runs a deterministic tie-break: only
the loser side (smaller NodeId) kills its egress; the winner side
returns `DropNew` and the new ingress is disconnected via a Custom
disconnect — a different log path. So "Remove old session" kills only
ever accumulate on one side of the pair.

The test runs many disconnect/reconnect cycles on two pairs of nodes in
parallel and asserts that, in each pair, "Remove old session" kills
appear on at most one side. With the bug, both sides accumulate kills
and the assertion trips.
"""

import os
import sys
import threading
import time

sys.path.insert(1, os.path.dirname(sys.path[0]))

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import disconnect_nodes, get_peer_addr, wait_until

# Each "Remove old session from the same node" kill produces exactly one
# log line matching this prefix (the actual kill_connection_by_token call).
# A different log line ("set token_to_disconnect to Some(...)") also contains
# the marker text — we use the more specific prefix to avoid double-counting.
SIMDIAL_KILL_MARKER = (
    'kill connection by token, deregister = true, '
    'reason = "Remove old session from the same node"'
)
TRIALS = 100


def count_pattern(node, pattern):
    """Count occurrences of `pattern` in node's conflux.log."""
    log_path = os.path.join(node.datadir, "conflux.log")
    try:
        with open(log_path, "r") as f:
            return f.read().count(pattern)
    except FileNotFoundError:
        return 0


class SimultaneousDialTest(ConfluxTestFramework):
    def set_test_params(self):
        # 4 nodes paired as (0, 1) and (2, 3). Both pairs run
        # simultaneous-dial trials in parallel, doubling the rate at
        # which the race condition is exercised.
        self.num_nodes = 4
        self.conf_parameters = {
            "discovery_housekeeping_timeout_ms": "100",
        }

    def setup_network(self):
        # Start the nodes isolated; the trigger function adds them as
        # mutual trusted peers and lets housekeeping dial them.
        self.setup_nodes()

    def trigger_simultaneous_reconnect_pair(self, i, j):
        """
        Disconnect the pair, then re-add each side as trusted from both
        nodes in parallel (via a Barrier) so the addNode RPCs land at
        essentially the same instant. Each node's next housekeeping
        cycle initiates an outbound against the freshly re-added trusted
        entry, and the two outbounds frequently overlap — the
        simultaneous-dial race window.
        """
        a, b = self.nodes[i], self.nodes[j]
        try:
            disconnect_nodes(self.nodes, i, j)
        except Exception as e:
            self.log.debug(f"disconnect_nodes({i}, {j}) failed: {e}")

        barrier = threading.Barrier(2)

        def add_a_to_b():
            barrier.wait()
            try:
                b.test_addNode(a.key, get_peer_addr(a))
            except Exception as e:
                self.log.debug(f"add_a_to_b failed: {e}")

        def add_b_to_a():
            barrier.wait()
            try:
                a.test_addNode(b.key, get_peer_addr(b))
            except Exception as e:
                self.log.debug(f"add_b_to_a failed: {e}")

        t1 = threading.Thread(target=add_b_to_a)
        t2 = threading.Thread(target=add_a_to_b)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        try:
            wait_until(
                lambda: any(
                    peer["nodeid"] == b.key
                    for peer in a.test_getPeerInfo()
                ),
                timeout=5,
            )
        except Exception:
            pass

    def run_test(self):
        # Run many disconnect/reconnect cycles on both pairs in parallel.
        for trial in range(TRIALS):
            if (trial + 1) % 10 == 0:
                self.log.info(f"Trial {trial + 1}/{TRIALS}")
            t_pair01 = threading.Thread(
                target=self.trigger_simultaneous_reconnect_pair,
                args=(0, 1),
            )
            t_pair23 = threading.Thread(
                target=self.trigger_simultaneous_reconnect_pair,
                args=(2, 3),
            )
            t_pair01.start()
            t_pair23.start()
            t_pair01.join()
            t_pair23.join()
            time.sleep(0.05)

        # Allow any in-flight kills to flush to the log.
        time.sleep(1.0)

        kills = [count_pattern(n, SIMDIAL_KILL_MARKER) for n in self.nodes]
        total = sum(kills)
        self.log.info(
            f"After {TRIALS} trials: kills per node = {kills}, total = {total}"
        )

        # Bug-detection assertion: with the bug, each successful
        # simultaneous-dial race causes BOTH sides of the pair to kill
        # their own egress (each side's update_ingress_node_id replaces
        # the existing entry and returns the old token for
        # kill_connection_by_token to log "Remove old session from the
        # same node"). Over many trials, kills accumulate on both sides
        # of each pair.
        #
        # With the fix, only the LOSER side of each pair (the one with
        # the smaller NodeId) kills its egress; the WINNER side returns
        # DropNew and the new ingress is disconnected via send_disconnect
        # (a different log path). So in each pair, kills accumulate on
        # exactly one side and the OTHER side has zero.
        pair_01_bilateral = kills[0] > 0 and kills[1] > 0
        pair_23_bilateral = kills[2] > 0 and kills[3] > 0
        assert not (pair_01_bilateral or pair_23_bilateral), (
            f"simultaneous-dial bug: 'Remove old session' kills observed "
            f"on BOTH sides of a pair: kills={kills}. "
            f"With the network-layer tie-breaking fix, only the loser side "
            f"(smaller NodeId) of each pair should produce these kills."
        )

        # Sanity: at least one pair must have fired some races, otherwise
        # the test isn't exercising the target code path.
        assert total > 0, (
            f"no simultaneous-dial events fired in {TRIALS} trials; "
            f"the test isn't exercising the target code path"
        )


if __name__ == "__main__":
    SimultaneousDialTest().main()
