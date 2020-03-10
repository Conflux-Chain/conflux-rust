#!/usr/bin/env python3

import argparse
import os
import time

def execute(cmd, retry, cmd_description):
    while True:
        ret = os.system(cmd)
        if ret == 0:
            break

        print("Failed to {}, return code = {}, retry = {} ...".format(cmd_description, ret, retry))
        assert retry > 0
        retry -= 1
        time.sleep(1)

def pssh(ips_file:str, remote_cmd:str, retry=0, cmd_description=""):
    cmd = f'parallel-ssh -O "StrictHostKeyChecking no" -h "{ips_file}" -p 400 "{remote_cmd}" > /dev/null 2>&1'
    execute(cmd, retry, cmd_description)

def pscp(ips_file:str, local:str, remote:str, retry=0, cmd_description=""):
    cmd = f'parallel-scp -O "StrictHostKeyChecking no" -h "{ips_file}" -p 400 "{local}" "{remote}" > /dev/null 2>&1'
    execute(cmd, retry, cmd_description)

def kill_remote_conflux(ips_file:str):
    pssh(ips_file, "killall conflux || echo already killed", 3, "kill remote conflux")

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
        self.enable_flamegraph = False

        self.exp_name = "latency_latest"
        self.nodes_per_host = 1
        self.block_sync_step = 10
        self.connect_peers = 8
        self.ips_file = "ips"
        self.throttling = "512,1024,2048"
        self.storage_memory_gb = 2
        self.bandwidth = 20
        self.tps = 4000
        self.enable_tx_propagation = False
        self.min_peers_propagate = 8
        self.max_peers_propagate = 128
        self.metrics_report_interval_ms = 3000
        self.send_tx_period_ms = 1300
        self.txgen_account_count= int((os.path.getsize("./genesis_secrets.txt")/65)//self.slave_count)
        self.slave_count=10

        self.batch_config = "500:1:150000:1000,500:1:200000:1000,500:1:250000:1000,500:1:300000:1000,500:1:350000:1000"

        # FIXME: we must specify what can be passed as arg.
        ArgumentHolder.__init__(self)

        if os.path.getsize("./genesis_secrets.txt") % 65 != 0:
            print("genesis secrets account error, file size should be multiple of 65")
            exit()


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

            print("Collecting metrics ...")
            tag = self.tag(config)
            execute("./copy_file_from_slave.sh metrics.log {} > /dev/null".format(tag), 3, "collect metrics")
            if self.enable_flamegraph:
                try:
                    execute("./copy_file_from_slave.sh conflux.svg {} > /dev/null".format(tag), 10, "collect flamegraph")
                except:
                    print("Failed to copy flamegraph file conflux.svg, please try again via copy_file_from_slave.sh in manual")

            execute("cp exp.log {}.exp.log".format(tag), 3, "copy exp.log")

        print("=========================================================")
        print("archive the experiment results into [{}] ...".format(self.stat_archive_file))
        cmd = "tar cvfz {} {} *.exp.log *nodes.csv *.metrics.log".format(self.stat_archive_file, self.stat_log_file)
        if self.enable_flamegraph:
            cmd = cmd + " *.conflux.svg"
        os.system(cmd)

    def copy_remote_logs(self):
        execute("./copy_logs.sh > /dev/null", 3, "copy logs")
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
            "--storage-memory-gb", str(self.storage_memory_gb),
            "--tps", str(self.tps),
            "--tx-pool-size", str(1_000_000),
            "--bandwidth", str(self.bandwidth),
            "--metrics-report-interval-ms", str(self.metrics_report_interval_ms),
            "--send-tx-period-ms", str(self.send_tx_period_ms),
            "--txgen-account-count", str(self.txgen_account_count),
        ]

        if config.data_propagate_enabled:
            cmd.extend([
                "--data-propagate-enabled",
                "--data-propagate-interval-ms", str(config.data_propagate_interval_ms),
                "--data-propagate-size", str(config.data_propagate_size),
            ])

        if self.enable_tx_propagation:
            cmd.extend(["--enable-tx-propagation"])

        if self.enable_flamegraph:
            cmd.extend(["--enable-flamegraph"])

        cmd.extend([">", self.simulate_log_file])
        cmd = " ".join(cmd)

        print("[CMD]: {}".format(cmd))

        ret = os.system(cmd)
        assert ret == 0, "Failed to run remote simulator, return code = {}. Please check [{}] for more details".format(ret, self.simulate_log_file)

        os.system('grep "(ERROR)" {}'.format(self.simulate_log_file))

    def tag(self, config:RemoteSimulateConfig):
        block_size_kb = config.txs_per_block * config.tx_size // 1000
        return "{}ms_{}k_{}vms_{}nodes".format(
            config.block_gen_interval_ms,
            block_size_kb,
            self.vms,
            self.nodes_per_host,
        )

    def stat_latency(self, config:RemoteSimulateConfig):
        os.system("echo ============================================================ >> {}".format(self.stat_log_file))

        if config.data_propagate_enabled:
            os.system('echo "Data propagation enabled: interval = {}, size = {}" >> {}'.format(
                config.data_propagate_interval_ms, config.data_propagate_size, self.stat_log_file
            ))

        print("begin to statistic relay latency ...")
        ret = os.system("python3 stat_latency.py {0} logs {0}.csv >> {1}".format(self.tag(config), self.stat_log_file))
        assert ret == 0, "Failed to statistic block relay latency, return code = {}".format(ret)

        if self.stat_confirmation_latency:
            print("begin to statistic confirmation latency ...")
            ret = os.system("python3 stat_confirmation.py logs 4 >> {}".format(self.stat_log_file))
            assert ret == 0, "Failed to statistic block confirmation latency, return code = {}".format(ret)

if __name__ == "__main__":
    LatencyExperiment().run()
