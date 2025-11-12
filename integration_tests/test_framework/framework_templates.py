from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.rpc import RpcClient
from integration_tests.test_framework.util import connect_sample_nodes, sync_blocks
from integration_tests.test_framework.mininode import start_p2p_connection

class DefaultFramework(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["min_native_base_price"] = 10000
        self.conf_parameters["base_fee_burn_transition_height"] = 1
        self.conf_parameters["base_fee_burn_transition_number"] = 1

    def setup_network(self):
        self.setup_nodes()
        self.rpc = RpcClient(self.nodes[0])


# dev framework runs a single node in dev mode
# when recieveing a tx, it will pack and execute it(generate 5 blocks) immediately
class DefaultDevFramework(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["mode"] = "'dev'"

    def setup_network(self):
        self.setup_nodes()
        self.rpc = RpcClient(self.nodes[0])
        
    # do nothing because in dev mode
    def _setup_w3_block_control_middleware(self):
        pass

class DefaultPoSFramework(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4        
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        self.conf_parameters["pos_round_per_term"] = '10'

    def setup_network(self):
        self.log.info("setup nodes ...")
        self.setup_nodes()
        self.log.info("connect peers ...")
        connect_sample_nodes(self.nodes, self.log)
        self.log.info("sync up with blocks among nodes ...")
        sync_blocks(self.nodes)
        self.log.info("start P2P connection ...")
        start_p2p_connection(self.nodes)
