# CIP Activation Configuration

Each hardfork may involve two activation points: by **block height** or by **block number**. These terms have different meanings in Conflux:  

- **Block height** refers to the height of the pivot chain.  
- **Block number** represents the total number of blocks in the full ledger.  

Typically, the block height is smaller than the block number. For a deeper understanding, refer to the [Conflux Ledger Structure Overview](https://doc.confluxnetwork.org/docs/general/conflux-basics/consensus-mechanisms/proof-of-work/tree-graph).

## Configuration Hierarchy for CIP Activation Time

The activation time for a CIP is configured through a hierarchical approach:

### Highest Priority: CIP-Specific Configuration

If the CIP has its own configuration parameter, the activation point specified by this parameter takes the highest priority.

### Second Priority: Hardfork Configuration

If the CIP does not have its own configuration parameter or the user has not specified one, the activation point is determined by the configuration parameters of the hardfork to which the CIP belongs.

### Third Priority: Default Transition Time

If the hardfork configuration parameters are not specified, the system uses the default_transition_time parameter. This parameter sets both the transition_number and transition_height of the hardfork to the value of default_transition_time.

### Final Priority: Node Mode

If default_transition_time is not specified, the activation time is determined based on the node's mode:

For nodes in test or dev mode, the activation time is set to 1, meaning all CIPs are activated immediately after the blockchain starts.
For nodes in other modes, the activation time is set to infinity, meaning all CIPs are deactivated by default.
Recommendation
Configuring default_transition_time=1 is sufficient for launching a node with all the latest features, meeting most use cases. Fine-grained CIP activation configurations are primarily intended for developer debugging and are not recommended for mature products.

### Caution

While it is possible to modify the activation time and order of different CIPs using configuration parameters, deviating from the mainnet activation sequence (e.g., activating a CIP from V2.4 before a CIP from V2.1) may lead to unexpected outcomes.

## Hardfork & CIPs Configuration

The following are the hardfork and CIP activation configuration options introduced in each version of Conflux-Rust:

### v1.1

#### Hardfork Configuration

| Configuration Key               | CIP(s)                |
|---------------------------------|-----------------------|
| tanzanite_transition_height     | CIP39, CIP40          |

### v2.0

#### Hardfork Configuration

| Configuration Key               | CIP(s)                |
|---------------------------------|-----------------------|
| hydra_transition_number         | CIP43, CIP64, CIP71, CIP78, CIP92 |
| hydra_transition_height         | CIP76, CIP86 |

#### CIP Configuration

| Configuration Key               | CIP(s)                |
|---------------------------------|-----------------------|
| cip78_patch_transition_number   | CIP78 |
| cip90_transition_height         | CIP90 point a |
| cip90_transition_number         | CIP90 point b |

#### PoS chain Configuration

| Configuration Key               | CIP(s)                |
|---------------------------------|-----------------------|
| cip43_init_end_number           | CIP43 |
| pos_reference_enable_height     | |

### v2.1

#### hardfork Configuration

| Configuration Key               | CIP(s)                |
|---------------------------------|-----------------------|
| dao_vote_transition_number      | CIP97, CIP98, CIP94, CIP105 |
| dao_vote_transition_height      | CIP94 |

#### CIP Configuration

| Configuration Key               | CIP(s)                |
|---------------------------------|-----------------------|
| cip105_transition_number        | CIP105 |

### v2.2

#### Hardfork Configuration

| Configuration Key               | CIP(s)                |
|---------------------------------|-----------------------|
| sigma_fix_transition_number     |  |

### v2.3

#### CIP Configuration

| Configuration Key               | CIP(s)                |
|---------------------------------|-----------------------|
| cip107_transition_number        | CIP107 |
| cip112_transition_height        | CIP112 |
| cip118_transition_number        | CIP118 |
| cip119_transition_number        | CIP119 |

#### PoS chain Configuration

| Configuration Key               | CIP(s)                |
|---------------------------------|-----------------------|
| cip113_transition_height        | CIP113 |

### v2.4

#### Hardfork Configuration

| Configuration Key               | Required                        | CIP(s)                |
|---------------------------------|------------------------------------|-----------------------|
| base_fee_burn_transition_number |     | CIP131, CIP132, CIP133, CIP137, CIP144, CIP145, CIP-141,142,143 |
| base_fee_burn_transition_height |     | CIP130, CIP133, CIP1559 |

#### CIP Configuration

| Configuration Key                | CIP(s)                |
|---------------------------------|-----------------------|
| cip1559_transition_height       | CIP1559 |
| cancun_opcodes_transition_number| CIP-141,142,143 |

### v2.5

#### Hardfork Configuration

| Configuration Key               | Required                        | CIP(s)                |
|---------------------------------|------------------------------------|-----------------------|
| c2_fix_transition_height        |     |  |

### v2.6

#### Hardfork Configuration

| Configuration Key               | Required                        | CIP(s)                |
|---------------------------------|------------------------------------|-----------------------|
| eoa_code_transition_height     |     | CIP150 CIP151 CIP152 CIP154 CIP645 CIP7702 |
| align_evm_transition_height    |     |  |

#### CIP Configuration

| Configuration Key               | Required                        | CIP(s)                |
|---------------------------------|------------------------------------|-----------------------|
| cip151_transition_height     |     |  |
| cip645_transition_height     |     |  |

Note: `align_evm_transition_height` is a **devnet** only configuration. When this configuration is set, the node will align the canonical EVM opcodes gas cost. Which means the eSpace EVM is identical to the canonical EVM.

There is a [template file](https://github.com/Conflux-Chain/conflux-docker/blob/master/fullnode-configs/dev-node/devnode.toml) that contains the activation configurations for various CIPs, which can be used as a reference.