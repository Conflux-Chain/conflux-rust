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
    cmd = 'parallel-ssh -O "StrictHostKeyChecking no" -h {} -p 400 \"{}\" > /dev/null'.format(ips_file, remote_cmd)
    execute(cmd, retry, cmd_description)

def pscp(ips_file:str, local:str, remote:str, retry=0, cmd_description=""):
    cmd = 'parallel-scp -O "StrictHostKeyChecking no" -h {} -p 400 {} {} > /dev/null'.format(ips_file, local, remote)
    execute(cmd, retry, cmd_description)

def kill_remote_conflux(ips_file:str):
    pssh(ips_file, "killall -9 conflux || echo already killed", 3, "kill remote conflux")

def cleanup_remote_logs(ips_file:str):
    pssh(ips_file, "rm -f *.tgz *.out; rm -rf /tmp/conflux_test_*")

class ArgumentHolder:
    def __init__(self):
        parser = argparse.ArgumentParser(usage="%(prog)s [options]")
        
        for arg_name in self.__dict__.keys():
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

class RemoteSimulateArgs(ArgumentHolder):
    def __init__(self):
        self.nodes_per_host = 3
        self.generation_period_ms = 500
        self.num_blocks = 1000
        self.block_sync_step = 10
        self.txs_per_block = 1
        self.generate_tx_data_len = 600_000
        self.connect_peers = 3
        self.ips_file = "ips"
        self.throttling = "512,1024,2048"
        self.storage_memory_mb = 2
        self.data_propagate_enabled = False
        self.data_propagate_interval_ms = 1000
        self.data_propagate_size = 1000

        ArgumentHolder.__init__(self)

class LatencyExperiment(RemoteSimulateArgs):
    def __init__(self):
        self.cmd = ""
        self.vms = 10
        self.stat_confirmation_latency = False
        self.simulate_log_file = "exp.log"
        self.stat_log_file = "exp_stat_latency.log"
        self.stat_archive_file = "exp_stat_latency.tgz"

        self.generate_txs_data_len_group = "150000,200000,250000,300000,350000,400000"

        RemoteSimulateArgs.__init__(self)

    def run(self):
        if self.cmd == "tps":
            self.run_tps()
        else:
            if self.cmd == "":
                print("command not specified!")
            else:
                print("invalid command:", self.cmd)
            print("supported commands: tps")

    def run_tps(self):
        for tx_data_len in self.generate_txs_data_len_group.split(","):
            print("start TPS experiment, tx_data_len = {} ...".format(tx_data_len))
            
            print("kill remote conflux and cleanup logs ...")
            kill_remote_conflux(self.ips_file)
            cleanup_remote_logs(self.ips_file)

            print("Run remote simulator ...")
            self.run_remote_simulate(tx_data_len)

            print("Kill remote conflux and copy logs ...")
            kill_remote_conflux(self.ips_file)
            self.copy_remote_logs()
            cleanup_remote_logs(self.ips_file)

            print("Statistic logs ...")
            os.system("echo throttling logs: `grep -i thrott -r logs | wc -l`")
            os.system("echo error logs: `grep -i thrott -r logs | wc -l`")

            print("Computing latencies ...")
            block_size_kb = self.txs_per_block * tx_data_len // 1000
            self.stat_latency(self.generation_period_ms, block_size_kb)

        os.system("tar cvfz {} {} *.csv".format(self.stat_archive_file, self.stat_log_file))

    def copy_remote_logs(self):
        ret = os.system("sh copy_logs.sh > /dev/null")
        assert ret == 0, "failed to copy remote logs to local, return code = {}".format(ret)
        os.system("echo `ls logs/logs_tmp | wc -l` logs copied.")

    def run_remote_simulate(self, tx_data_len):
        cmd = " ".join([
            "python3 ../remote_simulate.py",
            "--nodes-per-host", str(self.nodes_per_host),
            "--generation-period-ms", str(self.generation_period_ms),
            "--num-blocks", str(self.num_blocks),
            "--block-sync-step", str(self.block_sync_step),
            "--txs-per-block", str(self.txs_per_block),
            "--generate-tx-data-len", str(tx_data_len),
            "--connect-peers", str(self.connect_peers),
            "--ips-file", self.ips_file,
            "--throttling", self.throttling,
            "--data-propagate-enabled", str(self.data_propagate_enabled).lower(),
            "--data-propagate-interval-ms", str(self.data_propagate_interval_ms),
            "--data-propagate-size", str(self.data_propagate_size),
            ">", self.simulate_log_file
        ])

        ret = os.system(cmd)
        assert ret == 0, "Failed to run remote simulator, return code = {}. Please check [{}] for more details".format(ret, self.simulate_log_file)

        os.system('grep "(ERROR)" {}'.format(self.simulate_log_file))

    def stat_latency(self, block_interval_ms, block_size_kb):
        tag = "{}ms_{}k_{}vms_{}nodes".format(
            block_interval_ms,
            block_size_kb,
            self.vms,
            self.nodes_per_host,
        )

        os.system("echo ============================================================ >> {}".format(self.stat_log_file))

        print("begin to statistic relay latency ...")
        ret = os.system("python3 stat_latency.py {0} logs {0}.csv >> {1}".format(tag, self.stat_log_file))
        assert ret == 0, "Failed to statistic block relay latency, return code = {}".format(ret)

        print("begin to statistic confirmation latency ...")
        ret = os.system("python3 stat_confirmation.py logs 4 >> {}".format(self.stat_log_file))
        assert ret == 0, "Failed to statistic block confirmation latency, return code = {}".format(ret)

if __name__ == "__main__":
    # LatencyExperiment().run()
    print(RemoteSimulateArgs().__dict__)
