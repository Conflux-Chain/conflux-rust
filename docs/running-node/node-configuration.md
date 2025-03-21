# Node Configuration

The Conflux node configuration file is a TOML file. You can modify this file to configure the node's behavior.

The official documentation provides an [introduction to the main configuration options](https://doc.confluxnetwork.org/docs/general/run-a-node/advanced-topics/node-configuration), where you can find the most commonly used configuration options along with their descriptions.

In the `run` directory of this repository, there is a default configuration file, usually named `hydra.toml` (for mainnet) or `testnet.toml` (for testnet). This file contains almost all available configuration options with comments. You can modify this file to configure your node.

The configuration file path can be specified using the command-line parameter `--config`, for example:

```shell
./conflux --config /path/to/your/config.toml
```

## Hardfork Configurations

As the Conflux network evolves, we introduce new features, fix bugs, and improve network performance through hard forks. Any changes involving consensus rule modifications are introduced via [CIPs (Conflux Improvement Proposals)](https://github.com/conflux-chain/cips), and each hard fork may include one or more CIPs.

For a complete list of historically activated CIPs, refer to [this page](https://github.com/conflux-chain/cips?tab=readme-ov-file#activated). The list of all past hard forks can be found [here](https://github.com/conflux-chain/cips?tab=readme-ov-file#list-of-hardforks).

Typically, node operators do not need to manually configure hard fork settings, as the upgrade heights for both the mainnet and testnet are fixed. However, if you are setting up a [private network](https://doc.confluxnetwork.org/docs/general/run-a-node/advanced-topics/running-independent-chain), you may need to specify the activation height for each CIP according to your requirements.

There are two ways to specify activation heights: by **block height** or by **block number**. These terms have different meanings in Conflux:  
- **Block height** refers to the height of the pivot chain.  
- **Block number** represents the total number of blocks in the full ledger.  

Typically, the block height is smaller than the block number. For a deeper understanding, refer to the [Conflux Ledger Structure Overview](https://doc.confluxnetwork.org/docs/general/conflux-basics/consensus-mechanisms/proof-of-work/tree-graph).

The following are the CIP activation configuration options introduced in each version of Conflux-Rust:

### v1.1

| Configuration Key               | Required                        | CIP(s)                |
|---------------------------------|------------------------------------|-----------------------|
| tanzanite_transition_height     | ✅    | CIP40                 |

### v2.0

| Configuration Key               | Required                        | CIP(s)                |
|---------------------------------|------------------------------------|-----------------------|
| hydra_transition_number         | ✅    | CIP43a, CIP64, CIP71, CIP78a, CIP92 |
| hydra_transition_height         | ✅    | CIP76, CIP86 |
| cip43_init_end_number           | ✅    | CIP43b |
| pos_reference_enable_height     | ✅    | |
| cip78_patch_transition_number   |     | CIP78b |
| cip90_transition_height         |     | CIP90a |
| cip90_transition_number         |     | CIP90b |

There are two configuration options for setting the proportion of eSpace transactions in the overall block space.:

```toml
# The following parameter controls how many blocks are allowed to
# contain EVM Space transactions. Setting it to N means that one block
# must has a height of the multiple of N to contain EVM transactions.
evm_transaction_block_ratio=5
# The following parameter controls the ratio of gas limit allowed for
# EVM space transactions. Setting it to N means that only 1/N of th
# block gas limit can be used for EVM transaction enabled blocks.
evm_transaction_gas_ratio=2
```

### v2.1

| Configuration Key               | Required                        | CIP(s)                |
|---------------------------------|------------------------------------|-----------------------|
| dao_vote_transition_number      | ✅    | CIP97, CIP98, CIP94n, CIP105 |
| dao_vote_transition_height      | ✅    | CIP94h |
| cip105_transition_number        |     | CIP105 |

### v2.2

| Configuration Key               | Required                        | CIP(s)                |
|---------------------------------|------------------------------------|-----------------------|
| sigma_fix_transition_number     | ✅    |  |

### v2.3

| Configuration Key               | Required                        | CIP(s)                |
|---------------------------------|------------------------------------|-----------------------|
| cip107_transition_number        | ✅    | CIP107 |
| cip112_transition_height        | ✅    | CIP112 |
| cip118_transition_number        | ✅    | CIP118 |
| cip119_transition_number        | ✅    | CIP119 |

### v2.4

| Configuration Key               | Required                        | CIP(s)                |
|---------------------------------|------------------------------------|-----------------------|
| next_hardfork_transition_number | ✅    | CIP131, CIP132, CIP133b, CIP137, CIP144, CIP145, Cancun Opcodes |
| next_hardfork_transition_height | ✅    | CIP130, CIP133, CIP1559 |
| cip1559_transition_height       |     | CIP1559 |
| cancun_opcodes_transition_number|     | Cancun Opcodes |

There are two configuration options for setting the minimum base price of Core Space and eSpace.:

```toml
min_native_base_price=1000000000 # 1 GDrip
min_eth_base_price=1000000000 # 1 GDrip
```

### v2.5

| Configuration Key               | Required                        | CIP(s)                |
|---------------------------------|------------------------------------|-----------------------|
| c2_fix_transition_height        | ✅    |  |

### v2.6

| Configuration Key               | Required                        | CIP(s)                |
|---------------------------------|------------------------------------|-----------------------|
| eoa_code_transition_height     | ✅    | CIP7702  |
| align_evm_transition_height     |     |  |

Note: `align_evm_transition_height` is a **devnet** only configuration. When this configuration is set, the node will align the canonical EVM opcodes gas cost. Which means the eSpace EVM is identical to the canonical EVM.

There is a [template file](https://github.com/Conflux-Chain/conflux-docker/blob/master/fullnode-configs/dev-node/devnode.toml) that contains the activation configurations for various CIPs, which can be used as a reference.
