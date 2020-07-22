#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import argparse
from remote_simulate import RemoteSimulate, pssh, kill_remote_conflux, execute
import subprocess
from test_framework.test_framework import OptionHelper

def cleanup_remote_logs(ips_file:str):
    pssh(ips_file, "rm -f *.tgz *.out; rm -rf /tmp/conflux_test_*")

def setup_bandwidth_limit(ips_file:str, bandwidth: float, nodes_per_host: int):
    pssh(ips_file, f"./throttle_bitcoin_bandwidth.sh {bandwidth} {nodes_per_host}")

class RemoteSimulateConfig:
    def __init__(self, block_gen_interval_ms, txs_per_block, tx_size, num_blocks):
        self.block_gen_interval_ms = block_gen_interval_ms
        self.txs_per_block = txs_per_block
        self.tx_size = tx_size
        self.num_blocks = num_blocks

    def __str__(self):
        return str(self.__dict__)

    @staticmethod
    def parse(batch_config):
        config_groups = []
        if batch_config[-1] == ",":
            # Ignore trailing comma
            batch_config = batch_config[:-1]
        for config in batch_config.split(","):
            fields = config.split(":")
            if len(fields) != 4:
                raise AssertionError("invalid config, format is <block_gen_interval_ms>:<txs_per_block>:<tx_size>:<num_blocks>")
            config_groups.append(RemoteSimulateConfig(
                int(fields[0]),
                int(fields[1]),
                int(fields[2]),
                int(fields[3]),
            ))

        return config_groups

class LatencyExperiment:
    def __init__(self):
        self.exp_name = "latency_latest"
        self.stat_confirmation_latency = False
        self.simulate_log_file = "exp.log"
        self.stat_log_file = "exp_stat_latency.log"
        self.stat_archive_file = "exp_stat_latency.tgz"

        parser = argparse.ArgumentParser(usage="%(prog)s [options]")
        self.exp_latency_options = dict(
            vms = 10,
            batch_config = "500:1:150000:1000,500:1:200000:1000,500:1:250000:1000,500:1:300000:1000,500:1:350000:1000",
        )
        OptionHelper.add_options(parser, self.exp_latency_options)

        def k_from_kv(kv):
            (k, v) = kv
            return k

        remote_simulate_options = dict(filter(
            lambda kv: k_from_kv(kv) in set(["bandwidth", "profiler", "enable_tx_propagation", "ips_file", "enable_flamegraph"]),
            list(RemoteSimulate.SIMULATE_OPTIONS.items())))
        remote_simulate_options.update(RemoteSimulate.PASS_TO_CONFLUX_OPTIONS)
        # Configs with different default values than RemoteSimulate
        remote_simulate_options["nodes_per_host"] = 1
        remote_simulate_options["storage_memory_gb"] = 2
        remote_simulate_options["connect_peers"] = 8
        remote_simulate_options["tps"] = 4000

        OptionHelper.add_options(parser, remote_simulate_options)
        self.options = parser.parse_args()

        if os.path.getsize("./genesis_secrets.txt") % 65 != 0:
            print("genesis secrets account error, file size should be multiple of 65")
            exit()
        self.options.txgen_account_count = int((os.path.getsize("./genesis_secrets.txt")/65) //
                                               (self.options.vms * self.options.nodes_per_host))

    def run(self):
        for config in RemoteSimulateConfig.parse(self.options.batch_config):
            print("=========================================================")
            print("Experiment started, config = {} ...".format(config))
            
            print("kill remote conflux and cleanup logs ...")
            kill_remote_conflux(self.options.ips_file)
            cleanup_remote_logs(self.options.ips_file)
            setup_bandwidth_limit(self.options.ips_file, self.options.bandwidth, self.options.nodes_per_host)

            print("Run remote simulator ...")
            self.run_remote_simulate(config)

            print("Kill remote conflux and copy logs ...")
            kill_remote_conflux(self.options.ips_file)
            self.copy_remote_logs()
            # Do not cleanup logs here because they may be needed for debug later, and they will be deleted when the
            # next run begins
            # cleanup_remote_logs(self.options.ips_file)

            print("Statistic logs ...")
            os.system("echo throttling logs: `grep -i thrott -r logs | wc -l`")
            os.system("echo error logs: `grep -i thrott -r logs | wc -l`")

            print("Computing latencies ...")
            self.stat_latency(config)

            print("Collecting metrics ...")
            tag = self.tag(config)
            execute("./copy_file_from_slave.sh metrics.log {} > /dev/null".format(tag), 3, "collect metrics")
            execute("./copy_file_from_slave.sh conflux.log {} > /dev/null".format(tag), 3, "collect rust log")
            if self.options.enable_flamegraph:
                try:
                    execute("./copy_file_from_slave.sh conflux.svg {} > /dev/null".format(tag), 10, "collect flamegraph")
                except:
                    print("Failed to copy flamegraph file conflux.svg, please try again via copy_file_from_slave.sh in manual")

            execute("cp exp.log {}.exp.log".format(tag), 3, "copy exp.log")

        print("=========================================================")
        print("archive the experiment results into [{}] ...".format(self.stat_archive_file))
        cmd = "tar cvfz {} {} *.exp.log *nodes.csv *.metrics.log *.conflux.log".format(self.stat_archive_file, self.stat_log_file)
        if self.options.enable_flamegraph:
            cmd = cmd + " *.conflux.svg"
        os.system(cmd)

    def copy_remote_logs(self):
        execute("./copy_logs.sh > /dev/null", 3, "copy logs")
        os.system("echo `ls logs/logs_tmp | wc -l` logs copied.")

    def run_remote_simulate(self, config:RemoteSimulateConfig):
        cmd = [
            "python3",
            "../remote_simulate.py",
            "--generation-period-ms", str(config.block_gen_interval_ms),
            "--num-blocks", str(config.num_blocks),
            "--txs-per-block", str(config.txs_per_block),
            "--generate-tx-data-len", str(config.tx_size),
            "--tx-pool-size", str(1_000_000),
            "--conflux-binary", "~/conflux",
            "--nocleanup"
        ] + OptionHelper.parsed_options_to_args(
            dict(filter(lambda kv: kv[0] not in self.exp_latency_options, vars(self.options).items()))
        )

        log_file = open(self.simulate_log_file, "a")
        print("[CMD]: {} >> {}".format(cmd, self.simulate_log_file))
        ret = subprocess.run(cmd, stdout = log_file, stderr=log_file).returncode
        assert ret == 0, "Failed to run remote simulator, return code = {}. Please check [{}] for more details".format(ret, self.simulate_log_file)

        os.system('grep "(ERROR)" {}'.format(self.simulate_log_file))

    def tag(self, config:RemoteSimulateConfig):
        block_size_kb = config.txs_per_block * config.tx_size // 1000
        return "{}ms_{}k_{}vms_{}nodes".format(
            config.block_gen_interval_ms,
            block_size_kb,
            self.options.vms,
            self.options.nodes_per_host,
        )

    def stat_latency(self, config:RemoteSimulateConfig):
        os.system("echo ============================================================ >> {}".format(self.stat_log_file))

        print("begin to statistic relay latency ...")
        ret = os.system("python3 stat_latency.py {0} logs {0}.csv >> {1}".format(self.tag(config), self.stat_log_file))
        assert ret == 0, "Failed to statistic block relay latency, return code = {}".format(ret)

        if self.stat_confirmation_latency:
            print("begin to statistic confirmation latency ...")
            ret = os.system("python3 stat_confirmation.py logs 4 >> {}".format(self.stat_log_file))
            assert ret == 0, "Failed to statistic block confirmation latency, return code = {}".format(ret)


if __name__ == "__main__":
    LatencyExperiment().run()
