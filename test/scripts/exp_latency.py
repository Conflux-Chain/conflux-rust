#!/usr/bin/env python3

import argparse
import os


def execute(cmd, retry, cmd_description):
    while True:
        ret = os.system(cmd)
        if ret == 0:
            break

        print("Failed to {}, return code = {}, retry = {} ...".format(cmd_description, ret, retry))
        assert retry > 0
        retry -= 1

def pssh(ips_file:str, remote_cmd:str, retry=0, cmd_description=""):
    cmd = 'parallel-ssh -O "StrictHostKeyChecking no" -h {} -p 400 \"{}\" > /dev/null 2>&1'.format(ips_file, remote_cmd)
    execute(cmd, retry, cmd_description)

def pscp(ips_file:str, local:str, remote:str, retry=0, cmd_description=""):
    cmd = 'parallel-scp -O "StrictHostKeyChecking no" -h {} -p 400 {} {} > /dev/null 2>&1'.format(ips_file, local, remote)
    execute(cmd, retry, cmd_description)

def kill_remote_conflux(ips_file:str):
    pssh(ips_file, "killall -9 conflux || echo already killed", 3, "kill remote conflux")

def cleanup_remote_logs(ips_file:str):
    pssh(ips_file, "rm -f *.tgz *.out; rm -rf /tmp/conflux_test_*")

class ArgumentHolder:
    def __init__(self):
        parser = argparse.ArgumentParser(usage="%(prog)s [options]")
        
        for arg_name in self.__dict__.keys():
            if type(self.__dict__[arg_name]) == bool:
                parser.add_argument(
                    "--" + str(arg_name).replace("_", "-"),
                    dest=arg_name,
                    action='store_true',
                )
            else:
                parser.add_argument(
                    "--" + str(arg_name).replace("_", "-"),
                    dest=arg_name,
                    default=self.__dict__[arg_name],
                    type=type(self.__dict__[arg_name])
                )

        options = parser.parse_args()

        for arg_name in self.__dict__.keys():
            self.__dict__[arg_name] = getattr(options, arg_name)

    def usage(self):
        print("[Options]")
        for arg_name in self.__dict__.keys():
            print("{} <{}> ({})".format(
                "--" + str(arg_name).replace("_", "-"), 
                type(self.__dict__[arg_name]).__name__, 
                self.__dict__[arg_name]
            ))

class RemoteSimulateConfig:
    def __init__(self, block_gen_interval_ms, txs_per_block, tx_size, num_blocks):
        self.block_gen_interval_ms = block_gen_interval_ms
        self.txs_per_block = txs_per_block
        self.tx_size = tx_size
        self.num_blocks = num_blocks

        self.data_propagate_enabled = False
        self.data_propagate_interval_ms = 500
        self.data_propagate_size = 1000

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
            if len(fields) != 4 and len(fields) != 6:
                raise AssertionError("invalid config, format is <block_gen_interval_ms>:<txs_per_block>:<tx_size>:<num_blocks>:[<data_propagate_interval_ms>:<data_propagate_size>]")
            config_groups.append(RemoteSimulateConfig(
                int(fields[0]),
                int(fields[1]),
                int(fields[2]),
                int(fields[3]),
            ))

            if len(fields) == 6:
                config_groups[-1].data_propagate_enabled = True
                config_groups[-1].data_propagate_interval_ms = int(fields[4])
                config_groups[-1].data_propagate_size = int(fields[5])

        return config_groups

class LatencyExperiment(ArgumentHolder):
    def __init__(self):
        self.vms = 10
        self.stat_confirmation_latency = False
        self.simulate_log_file = "exp.log"
        self.stat_log_file = "exp_stat_latency.log"
        self.stat_archive_file = "exp_stat_latency.tgz"

        self.exp_name = "latency_latest"
        self.nodes_per_host = 1
        self.block_sync_step = 10
        self.connect_peers = 8
        self.ips_file = "ips"
        self.throttling = "512,1024,2048"
        self.data_propagate_enabled = False
        self.data_propagate_interval_ms = 1000
        self.data_propagate_size = 1000
        self.storage_memory_mb = 2
        self.bandwidth = 20
        self.tps = 4000
        self.enable_tx_propagation = False

        self.batch_config = "500:1:150000:1000,500:1:200000:1000,500:1:250000:1000,500:1:300000:1000,500:1:350000:1000"

        ArgumentHolder.__init__(self)

    def run(self):
        for config in RemoteSimulateConfig.parse(self.batch_config):
            print("=========================================================")
            print("Experiment started, config = {} ...".format(config))
            
            print("kill remote conflux and cleanup logs ...")
            kill_remote_conflux(self.ips_file)
            cleanup_remote_logs(self.ips_file)

            print("Run remote simulator ...")
            self.run_remote_simulate(config)

            print("Kill remote conflux and copy logs ...")
            kill_remote_conflux(self.ips_file)
            self.copy_remote_logs()
            # Do not cleanup logs here because they may be needed for debug later, and they will be deleted when the
            # next run begins
            # cleanup_remote_logs(self.ips_file)

            print("Statistic logs ...")
            os.system("echo throttling logs: `grep -i thrott -r logs | wc -l`")
            os.system("echo error logs: `grep -i thrott -r logs | wc -l`")

            print("Computing latencies ...")
            self.stat_latency(config)

        print("=========================================================")
        print("archive the experiment results into [{}] ...".format(self.stat_archive_file))
        os.system("tar cvfz {} {} *.csv".format(self.stat_archive_file, self.stat_log_file))

    def copy_remote_logs(self):
        execute("sh copy_logs.sh > /dev/null", 3, "copy logs")
        os.system("echo `ls logs/logs_tmp | wc -l` logs copied.")

    def run_remote_simulate(self, config:RemoteSimulateConfig):
        cmd = [
            "python3 ../remote_simulate.py",
            "--nodes-per-host", str(self.nodes_per_host),
            "--generation-period-ms", str(config.block_gen_interval_ms),
            "--num-blocks", str(config.num_blocks),
            "--block-sync-step", str(self.block_sync_step),
            "--txs-per-block", str(config.txs_per_block),
            "--generate-tx-data-len", str(config.tx_size),
            "--connect-peers", str(self.connect_peers),
            "--ips-file", self.ips_file,
            "--throttling", self.throttling,
            "--storage-memory-mb", str(self.storage_memory_mb),
            "--tps", str(self.tps),
            "--bandwidth", str(self.bandwidth)
        ]

        if config.data_propagate_enabled:
            cmd.extend([
                "--data-propagate-enabled",
                "--data-propagate-interval-ms", str(config.data_propagate_interval_ms),
                "--data-propagate-size", str(config.data_propagate_size),
            ])

        if self.enable_tx_propagation:
            cmd.extend(["--enable-tx-propagation"])

        cmd.extend([">", self.simulate_log_file])
        cmd = " ".join(cmd)

        print("[CMD]: {}".format(cmd))

        ret = os.system(cmd)
        assert ret == 0, "Failed to run remote simulator, return code = {}. Please check [{}] for more details".format(ret, self.simulate_log_file)

        os.system('grep "(ERROR)" {}'.format(self.simulate_log_file))

    def stat_latency(self, config:RemoteSimulateConfig):
        block_size_kb = config.txs_per_block * config.tx_size // 1000

        tag = "{}ms_{}k_{}vms_{}nodes".format(
            config.block_gen_interval_ms,
            block_size_kb,
            self.vms,
            self.nodes_per_host,
        )

        os.system("echo ============================================================ >> {}".format(self.stat_log_file))

        if config.data_propagate_enabled:
            os.system('echo "Data propagation enabled: interval = {}, size = {}" >> {}'.format(
                config.data_propagate_interval_ms, config.data_propagate_size, self.stat_log_file
            ))

        print("begin to statistic relay latency ...")
        ret = os.system("python3 stat_latency.py {0} logs {0}.csv >> {1}".format(tag, self.stat_log_file))
        assert ret == 0, "Failed to statistic block relay latency, return code = {}".format(ret)

        if self.stat_confirmation_latency:
            print("begin to statistic confirmation latency ...")
            ret = os.system("python3 stat_confirmation.py logs 4 >> {}".format(self.stat_log_file))
            assert ret == 0, "Failed to statistic block confirmation latency, return code = {}".format(ret)

if __name__ == "__main__":
    LatencyExperiment().run()
