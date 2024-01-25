# End-to-end Evaluation for Authenticated Storages

## Introduction

This evaluation program, derived from the Conflux-rust repository, offers the ability to compile with multiple authenticated storage systems, enabling comprehensive end-to-end performance testing. By leveraging the Conflux integration testing framework, the program dispatches random transfer transactions of both native tokens and ERC20 tokens to blockchain nodes. It then gathers an extensive raw trace of performance metric data, which can be utilized for in-depth analysis.

## Building the Project

The following steps outline how to build the project on Ubuntu 22.04.

### Prerequisites

- Ubuntu 22.04
- Rust (version 1.67.0)
- Python3 (version ≥3.8) and pip3
- Build tools: `build-essential`, `libssl-dev`, `pkg-config`, `libclang-dev`, `cmake`

### Steps

Follow the steps below to build the project:

1. Update the package list:
    
    ```bash
    sudo apt update
    ```
    
2. Install Rust and Cargo:
    
    ```bash
    sudo apt install rustc cargo
    ```
    
3. Install additional dependencies:
    
    ```bash
    sudo apt install build-essential libssl-dev pkg-config libclang-dev cmake
    ```
    
4. Clone the repository and navigate to the project directory:
    
    ```bash
    git clone --recursive https://github.com/Conflux-Chain/conflux-rust.git --branch asb-e2e
    cd conflux-rust
    ```
    
5. Create folders for experiment data:
    
    ```bash
    mkdir experiment_data
    mkdir experiment_data/metrics
    mkdir experiment_data/transactions
    ```
    
6. Build the project:
    
    ```bash
    ./run_bench.sh build
    ```
    
    **Note:** This command will build several binaries with different authenticated storages. The build time can range from 30 minutes to a few hours, depending on your CPU performance.
    
7. Install Python and Pip:
    
    ```bash
    sudo apt install python3 python3-pip
    ```
    
    **Note:** If you have Python 3 installed, we recommend creating a separate environment to avoid conflicts with existing installed packages.
    
8. Install Python dependency modules:
    
    ```bash
    ./dev-support/dep_pip3.sh
    ```
    
    **Note:** You may ignore any incompatible version errors reported by pip.

9. Before evaluating LVMT, create a designated folder named `pp` that will be used for storing all cryptography parameters.
    
    ```bash
    mkdir pp
    ```

    **Note:** When using LVMT for the first time, it may take anywhere from minutes to hours to initialize the cryptography parameters. Alternatively, you can [download the generated cryptography parameters](https://drive.google.com/file/d/1pHiHpZ4eNee17C63tSDEvmcEVtv23-jK/view?usp=sharing) and place the files in the folder `./pp`.
    
10. Generate random signed transactions for test
    
    ```bash
    python3 tests/asb-e2e/produce_tx.py
    ```
    
    This command may take hours to generate signed transactions. The bottleneck of transaction generation is generating public keys from private keys and signing transactions, which can be parallelized. A CPU with high multi-core performance can accelerate this process.
    
    Alternatively, you can [download the generated transactions](https://1drv.ms/f/s!Au7Bejk2NtCskWpGOUUNxC9Bu1cD?e=tcMttz), and place the folders `transfer` and `erc20` in the `experiment_data/transactions` folder.
    
11. Execute the preconfigured evaluation tasks (**Note:** ensure that no HTTP proxy is enabled):
    
    ```bash
    ./run_bench.sh
    ```
    
    This [instruction](#running-experiments-with-memory-constraints) can help you apply the memory limit constraint for evaluation tasks. The results will be saved in the `experiment_data/metrics/osdi23` directory. You can also tailor the evaluation by modifying compile features and script options. Refer to the guidance below for further information.

12. Use [asb-plotter](https://github.com/ChenxingLi/asb-plotter) to parse the experiment traces and plot figures.
    
Also you can customize the evaluation by compiling the node with different features and run the evaluation script with different options to suit your requirements. 

## Compile Features

To compile the node, run the following command:

```bash
cargo build --release
```

You can specify features by appending `--features <feature A> --features <feature B>`. For example, to enable the `pprof-profile` and `client/metric-goodput` features, run the following command:

```bash
cargo build --release --features pprof-profile --features client/metric-goodput
```

By default, the authenticated storage used in Conflux mainnet is Layered Merkle Patricia Tries (LMPTs)[2]. However, you can specify a different authenticated storage by enabling the corresponding feature. For example, to use the LVMT, enable the `lvmt-storage` feature. The available options are:

The default authenticated storage is Layered Merkle Patricia Tries (LMPTs)[2], which is used in Conflux mainnet. Specify one if the following authenticated storage by enabling corresponding feature. 
- `raw-storage`: No authenticated storage; writes changes directly to the backend.
- `lvmt-storage`: The [multi-Layer Versioned Multipoint Trie (LVMT)](https://github.com/ChenxingLi/authenticated-storage-benchmarks/tree/master/asb-authdb/lvmt-db)[1] in our new work.
- `rain-storage`: A modified version of [RainBlock's MPT](https://github.com/RainBlock/merkle-patricia-tree) [3], which stores the bottom layers locally on storage instead of using a distributed in-memory system as in the original work
- `mpt-storage`: [OpenEthereum's MPT implementation](https://github.com/openethereum/openethereum/tree/main/crates/db/patricia-trie-ethereum).


This program offers additional features for building Conflux-rust:

- `pprof-profile`: Generates a CPU profile during execution (collected by pprof-rs).
- `cfxcore/storage-dev`: Disables Conflux's additional EVM features like sponsor mechanism and storage collateral. If either authenticated storage features is enabled, this feature will also be enabled. 
- `cfxcore/bypass-txpool`: Bypasses Conflux's transaction pool, which supports up to 23,000 TPS, to prevent bottlenecks during evaluation.
- `cfxcore/light-hash-storage`: Replaces `keccak256` with the faster `blake2b` hash function.

## Evaluation Script Options

To evaluate the performance of the system, you can use the main evaluation script located at `tests/asb-e2e/main.py` with options in the following.

```
python3 tests/asb-e2e/main.py [options]
```

### Specifying the Backend

Set the `CONFLUX_DEV_STORAGE` environment variable to evaluate with different authenticated storage options:

- `raw`: No authenticated storage; writes changes directly to the backend.
- `lvmt`: The [multi-Layer Versioned Multipoint Trie (LVMT)](https://github.com/ChenxingLi/authenticated-storage-benchmarks/tree/master/asb-authdb/lvmt-db)[1] in our new work.
- `rain`: A modified version of [RainBlock's MPT](https://github.com/RainBlock/merkle-patricia-tree) [3], which stores the bottom layers locally on storage instead of using a distributed in-memory system as in the original work
- `mpt`: [OpenEthereum's MPT implementation](https://github.com/openethereum/openethereum/tree/main/crates/db/patricia-trie-ethereum).
- `lmpts`: The Layered Merkle Patricia Tries (LMPTs)[2] used in Conflux.

For `raw`, `lvmt`, `rain`, `mpt`, and `lmpts`, the Conflux full node binary will be loaded from `target/raw-db`, `target/lvmt-db`, `target/rain-db`, `target/mpt-db`, and `target` (default path of rust). When manually conducting evaluations for the first four cases, use `--target-dir <path>` in compilation.

**Note:** When using LVMT for the first time, it may take anywhere from minutes to hours to initialize the cryptography parameters. Alternatively, you can [download the generated cryptography parameters](https://drive.google.com/file/d/1pHiHpZ4eNee17C63tSDEvmcEVtv23-jK/view?usp=sharing) and place the files in the folder `./pp`.

### Using a Faster Hash Function

If you enable the `cfxcore/light-hash-storage` feature during compilation, set the `LIGHT_HASH` environment variable to `1` during evaluation to avoid errors.

### Evaluation Task Parameters

Two types of evaluation tasks are available: native token transfers and ERC20 token transfers. Specify them using `--bench-token native` and `--bench-token erc20`. Set the number of accounts in the experiment with `--bench-key <number>` and the number of transactions in the evaluation with `--bench-txs <number>`. Initialization transactions, such as distributing initial tokens for test accounts, are not included. The specified number of transactions cannot exceed the number of pre-generated signed transactions in `experiment_data/transactions`.

Our provided generated transactions support three different account sizes: 1 million, 3 million, and 5 million. For each case, transactions equivalent to five times the number of accounts are generated. Modify `ACCOUNT_SIZE_LIST` and `RANDOM_TXS` in `tests/asb-e2e/produce_tx/params.py` to generate tasks with different parameters.

For LVMT, configure the number of shards in proof sharding by setting the environment variable `LVMT_SHARD_SIZE` to the desired number of shards. The shard number must be a power of two, ranging from 1 to 65,536. If this option is not set, LVMT will not maintain the associated information required for proofs.

### Other Options

- `--port-min <port>`: The program will use several sequential TCP ports. This argument specifies the first occupied port.
- `--metric-folder <dir>`: Evaluation results will be written to `experiment_data/metrics/<dir>`.

## Running Experiments with Memory Constraints

Our paper's experiments were conducted with a memory limit of 16GB. If you don't have a machine with exactly 16GB of memory, you'll need to limit the memory through cgroup, Docker, or some other method. Below is a solution using cgroup, **assuming you have sudo privileges on the system.**

### Install CGroup and Set Memory Limit

Firstly, you need to install cgroup on your system. On Ubuntu, you can do this using the following command:

```bash
sudo apt-get install cgroup-bin
```

Then, create a cgroup named `lvmt` with a memory limit of 16GB:

```bash
sudo cgcreate -g memory:/lvmt-e2e
sudo cgset -r memory.limit_in_bytes=$((16*1024*1024*1024)) lvmt-e2e
```

### Configure Sudo Permissions

Next, ensure that `cgclassify` and `sysctl` can be run with sudo command without requiring a password. You can achieve this by adding the following lines to your sudoers:

```bash
<your_username> ALL=NOPASSWD: /usr/bin/cgclassify
<your_username> ALL=NOPASSWD: /sbin/sysctl
```

Replace `<your_username>` with your actual username. You can edit the sudoers file using `sudo visudo`, or use `vim` as your editor by:

```bash
sudo update-alternatives --set editor /usr/bin/vim.basic
sudo visudo
```

### Create and Configure the Shell Script

Create a shell script with the following content:

```bash
#!/bin/bash

# Classify the current shell into the 'lvmt' memory cgroup
sudo cgclassify -g memory:/lvmt-e2e $$
COMMAND=$@

bash -c "$COMMAND"
# Alternatively, if you want to load your custom environment 
# (e.g., defined in .zprofile) before executing the command, 
# run the following line instead.
# bash -c "source ~/.zprofile && $COMMAND"
```

This script allows you to execute a task with a constrained memory limit under regular user mode rather than a superuser mode.

Make sure to give this script execute permissions:

```
chmod +x <your_script.sh>
```

### Modify the Preconfigured Run Script

Edit the `run.sh` file to replace the `alias cgrun` with the path to the script you created in the previous step, e.g., `alias cgrun="/path/to/your_script.sh"`. 

This setup will ensure that your experiments run with a memory constraint of 16GB, closely replicating the conditions of the experiments in our paper.


## References

[1] Chenxing Li, Sidi Mohamed Beillahi, Guang Yang, Ming Wu, Wei Xu, and Fan Long. "LVMT: An Efﬁcient Authenticated Storage for Blockchain". In *2023 USENIX Symposium on Operating Systems Design and Implementation (OSDI)*. 2023.

[2] Choi, Jemin Andrew, Sidi Mohamed Beillahi, Peilun Li, Andreas Veneris, and Fan Long. "LMPTs: Eliminating Storage Bottlenecks for Processing Blockchain Transactions." In *2022 IEEE International Conference on Blockchain and Cryptocurrency (ICBC)*, pp. 1-9. IEEE, 2022.

[3] Ponnapalli, Soujanya, Aashaka Shah, Souvik Banerjee, Dahlia Malkhi, Amy Tai, Vijay Chidambaram, and Michael Wei. "RainBlock: Faster Transaction Processing in Public Blockchains." In *USENIX Annual Technical Conference*, pp. 333-347. 2021.
## License

[GNU General Public License v3.0](https://github.com/Conflux-Chain/conflux-rust/blob/master/LICENSE)