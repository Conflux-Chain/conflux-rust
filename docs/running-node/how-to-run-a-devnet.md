# How to Run a Multi-Node DevNet

For local testing, you may need to set up a multi-node Conflux DevNet. This document walks through the full process, from configuration preparation to startup and verification.

The key to running a multi-node DevNet is preparing the configuration correctly. The overall workflow is:

1. Get the Node IDs and IPs of your genesis nodes, then build `bootnodes`.
2. Generate PoS genesis-related files for the nodes.
3. Set critical options (such as `mining_type="cpu"` and `dev_allow_phase_change_without_peer=true`).
4. Start all nodes and verify that they are connected.

## Prerequisites

1. Install the [Conflux Rust development environment](../build-from-source.md), including the Rust compiler and related tools.
2. Clone the Conflux Rust repository.
3. Create a local Python environment and run `./dev-support/dep_pip3.sh` to install Python dependencies.
4. Run `cargo build --release` (this generates `./target/release/pos-genesis-tool`, used to create PoS genesis data).
5. The default mainnet config file `hydra.toml` is located in `./run`. Copy it as `devnet.toml` and modify it as needed.

## Build the `bootnodes` Configuration

1. Use `tests/tools/host_gen.py` to generate `net_key` (`net_pri_key`) and Node ID (`net_pub_key`) for genesis nodes.
2. Use the generated Node IDs and node IPs to build `bootnodes`, then replace the original value in `devnet.toml`.

The command below generates `net_pri_key` and `net_pub_key` (Node ID) for two nodes:

```sh
$ python3 tests/tools/host_gen.py

net_pri_key: "79cb7897851e7e111b0605f916d0457006bf6607d874b3897cbfb72f73c8b7fe"
net_pub_key: "20ce5e1a25af7bada3316c4af7f840115448671b88876e2918cd96339a6c61b6e6c0882925ced9e69fa665a1ac590f2815089d827fef179aaf0cadb0f01066fe"

net_pri_key: "75000159037c01c50374e65be345da94790c099a83c0587f32fb945d8ef80f97"
net_pub_key: "6a9499a1d51f0b7840cab2790204c32ae8975d6be95a1413ef33e12ebe5d11f98969b227e2bc94e3da5cfcf671b4227748b5b2212c7723b65c577a78d2091bd3"
```

Assume the two node IPs are `1.2.3.4` and `5.6.7.8`. Then `bootnodes` in `devnet.toml` can be:

```toml
bootnodes="cfxnode://20ce5e1a25af7bada3316c4af7f840115448671b88876e2918cd96339a6c61b6e6c0882925ced9e69fa665a1ac590f2815089d827fef179aaf0cadb0f01066fe@1.2.3.4:32323,cfxnode://6a9499a1d51f0b7840cab2790204c32ae8975d6be95a1413ef33e12ebe5d11f98969b227e2bc94e3da5cfcf671b4227748b5b2212c7723b65c577a78d2091bd3@5.6.7.8:32323,"
```

Note: `32323` is the default P2P port and can be changed if needed.

If you have more nodes, repeat the same process and include all nodes in the same `bootnodes` value. All nodes must use the same `bootnodes` configuration so they can discover each other.

The generated `net_pri_key` must be configured as each genesis node’s `net_key`. There are two options:

1. Write `net_pri_key` (without a trailing newline) to `blockchain_data/net_config/key`.
2. Set the `net_key` field in the config file.

Both are valid. Important: `net_pri_key` is bound to the node IP. Each node must use its own corresponding `net_pri_key`; otherwise it cannot join the DevNet correctly.

## Set `chain_id`

Set `chain_id` and `evm_chain_id` in the config file to your target values, for example:

```toml
chain_id=1234
evm_chain_id=1235
```

These correspond to the chain IDs for Conflux Core Space and eSpace.

## Generate PoS Genesis Configuration Files

1. Run the command below to generate PoS genesis data:
   `./target/release/pos-genesis-tool random --initial-seed=0000000000000000000000000000000000000000000000000000000000000000 --num-validator=3 --num-genesis-validator=3 --chain-id=1234`
2. Create a `pos_config` directory and place `initial_nodes.json`, and `pos_config.yaml` in it.
3. Step 1 generates multiple node private keys. Move each corresponding key from `private_keys` into `pos_config` and rename it to `pos_key`.

Example output directory after step 1:

```sh
$ tree
.
├── initial_nodes.json
├── private_keys
│   ├── 0
│   ├── 1
│   ├── 2
│   ├── pow_sk0
│   ├── pow_sk1
│   └── pow_sk2
└── public_key

2 directories, 9 files
```

The generated `pos_key` has an empty password by default.

Below is a `pos_config.yaml` template:

```yaml
base:
  #data_dir: ./pos_db
  role: validator
consensus:
  round_initial_timeout_ms: 60000
  safety_rules:
    service:
      type: local
logger:
  file: ./log/pos.log
  level: INFO
#storage:
  #dir: ./pos_db/db
```

## Set Critical Configuration Items

In `devnet.toml`, at minimum verify the following:

```toml
mining_type="cpu"
mining_author = "0x19619a70899B445859Fc86120CD9Ff74e6252A2D"
dev_allow_phase_change_without_peer=true
initial_difficulty=1000 # Set a low difficulty for testing. Adjust as needed.
```

`mining_author` must be a valid address (a hex address starting with `0x1`, or a base32 address).

## Configure Genesis Account Balances

```toml
genesis_accounts = "./genesis_accounts.txt"
```

`genesis_accounts.txt` format:

```txt
# Left: hex address without 0x (first digit must be 1). Right: balance in Drip.
# Use '=' as separator and do not add spaces. Example:
111C290704B850d2be9aC5F486fD7073B7ce4Ad9="1000000000000000000000"  # 1000 CFX
```

For other configuration items, refer to the [Config File Reference](https://doc.confluxnetwork.org/docs/general/run-a-node/advanced-topics/node-configuration).

## Start Nodes

Assuming your config file is `devnet.toml`, start a node with:

```sh
$ conflux --config devnet.toml
```

If prompted for a password, just press Enter (`pos_key` uses an empty password by default).

## Verify DevNet

Send a transaction on one node, wait for it to be packed, then query the transaction status on other nodes. If other nodes can also find the transaction, the DevNet is working properly.

## Summary

DevNet is highly flexible. You can tune parameters for local testing, such as activation heights of different CIPs and block size limits, to make integration testing and validation more efficient.
