# Node Configuration

The Conflux node configuration file is a TOML file. You can modify this file to configure the node's behavior.

The official documentation provides an [introduction to the main configuration options](https://doc.confluxnetwork.org/docs/general/run-a-node/advanced-topics/node-configuration), where you can find the most commonly used configuration options along with their descriptions.

In the `run` directory of this repository, there is a default configuration file, usually named `hydra.toml` (for mainnet) or `testnet.toml` (for testnet). This file contains almost all available configuration options with comments. You can modify this file to configure your node.

The configuration file path can be specified using the command-line parameter `--config`, for example:

```shell
./conflux --config /path/to/your/config.toml
```

## Activate CIPs that inherit the default transition time in a private network

As the Conflux network evolves, we introduce new features, fix bugs, and improve network performance through hard forks. Any changes involving consensus rule modifications are introduced via [CIPs (Conflux Improvement Proposals)](https://github.com/conflux-chain/cips), and each hard fork may include one or more CIPs.

For a complete list of historically activated CIPs, refer to [this page](https://github.com/conflux-chain/cips?tab=readme-ov-file#activated). The list of all past hard forks can be found [here](https://github.com/conflux-chain/cips?tab=readme-ov-file#list-of-hardforks).

Typically, node operators do not need to manually configure hard fork settings, as the upgrade heights for both the mainnet and testnet are fixed and hardcoded in the released Conflux node binaries. However, if you are setting up a [private network](https://doc.confluxnetwork.org/docs/general/run-a-node/advanced-topics/running-independent-chain), you may need to specify the activation height for each CIP according to your requirements.

For a private network, the following configuration activates at block 1 the
CIPs that inherit `default_transition_time` and enables PoS references from
height 1:

```toml
default_transition_time = 1
# CIP-1559 must activate no earlier than PoS references.
pos_reference_enable_height = 1
```

This does not override features with independent transition settings, such as
`tanzanite_transition_height`, `cip112_transition_height`, or
`align_evm_transition_height`. Configure those explicitly when they are
required.

More precise control over the activation timing of each feature is mainly used for code integration testing. If you are absolutely certain that you need to use this feature, please read [CIP configuration](./cips-configuration.md).
