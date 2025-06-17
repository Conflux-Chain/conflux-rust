# Node Configuration

The Conflux node configuration file is a TOML file. You can modify this file to configure the node's behavior.

The official documentation provides an [introduction to the main configuration options](https://doc.confluxnetwork.org/docs/general/run-a-node/advanced-topics/node-configuration), where you can find the most commonly used configuration options along with their descriptions.

In the `run` directory of this repository, there is a default configuration file, usually named `hydra.toml` (for mainnet) or `testnet.toml` (for testnet). This file contains almost all available configuration options with comments. You can modify this file to configure your node.

The configuration file path can be specified using the command-line parameter `--config`, for example:

```shell
./conflux --config /path/to/your/config.toml
```

## Enable all CIPs in private network

As the Conflux network evolves, we introduce new features, fix bugs, and improve network performance through hard forks. Any changes involving consensus rule modifications are introduced via [CIPs (Conflux Improvement Proposals)](https://github.com/conflux-chain/cips), and each hard fork may include one or more CIPs.

For a complete list of historically activated CIPs, refer to [this page](https://github.com/conflux-chain/cips?tab=readme-ov-file#activated). The list of all past hard forks can be found [here](https://github.com/conflux-chain/cips?tab=readme-ov-file#list-of-hardforks).

Typically, node operators do not need to manually configure hard fork settings, as the upgrade heights for both the mainnet and testnet are fixed and hardcoded in the released Conflux node binaries. However, if you are setting up a [private network](https://doc.confluxnetwork.org/docs/general/run-a-node/advanced-topics/running-independent-chain), you may need to specify the activation height for each CIP according to your requirements.

Most requirements for running a private network are to run an environment that includes all the latest features. Due to the peculiarities of the genesis block, features added by CIP cannot be activated in the genesis block. Therefore, the most common and simplest approach is to activate all features in the block immediately following the genesis block.

```toml
default_transition_time = 1
# cip1559 needs to be activated after the pos_reference_enable_height
pos_reference_enable_height = 1
```

This configuration will activate all implemented features at the first block after the genesis block.

More precise control over the activation timing of each feature is mainly used for code integration testing. If you are absolutely certain that you need to use this feature, please read [CIP configuration](./cips-configuration.md).
