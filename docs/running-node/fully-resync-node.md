# fully resync node

When running a Conflux `Archive` node, if you prefer not to use a data snapshot, you can choose to fully synchronize data from the network.

> Note: Syncing data from scratch can take a significant amount of time. As of November 26, 2024, syncing the Conflux mainnet data from scratch may take approximately 2 months.

In addition to the basic setup and operation, fully synchronizing a Conflux node requires downloading and configuring `PivotHint` data to ensure the accuracy of the data synchronization.

## Download PivotHint Data

### Mainnet

[Download Mainnet Pivot Hint Binary](https://conflux-blockchain-pivot-hint.s3.ap-east-1.amazonaws.com/mainnet-107000000-bd0b857b.cphb) (114.5 MB)
File SHA256 Checksum: 89957f388884f6374eb471d1b56a684c419c20edd9d00e89faa153fbf3e33207
Pivot Hint Checksum: bd0b857b6a78dbe5df45c61868df13675c27116721246b96f48ecb835d0915da

### Testnet

[Download Testnet Pivot Hint Binary](https://conflux-blockchain-pivot-hint.s3.ap-east-1.amazonaws.com/testnet-192900000-a793350e.cphb) (206.3 MB)
File SHA256 Checksum: c76abe509f5f975f0353e226d5b3020289ef7c353e031ba953de6b4f503848fa
Pivot Hint Checksum: a793350eafeeb9eef76c9b3e61661bf870042ba79ddf1c277800991b56fbe05d

## Configurations

Archive nodes can enable this feature by configuring:

* `pivot_hint_path`: Path to the pivot hint file
* `pivot_hint_checksum`: Expected checksum of Page Digests section (hex string without "0x" prefix)

Note: These two configurations must either both be specified or both be omitted. Specifying only one will result in an error.

## FAQs

1. When to Choose Full Synchronization?
   * If you do not trust snapshot data from third parties, full synchronization is often chosen, as in the case of exchanges.
   * If the snapshot data does not meet your requirements, such as wanting to run a fullstate node but no such snapshot is provided by Conflux official sources.
