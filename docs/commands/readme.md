# commands

In addition to serving as the main node software for running the Conflux network, the conflux binary also provides a set of command-line tools to help users perform various operations more conveniently.

Currently Available Subcommands：

- `account`：Account Management
- `rpc`：RPC-based subcommands, used for querying blockchain information and sending transactions
- `dump`: Dump eSpace account state at a given block number
- `help`：Print help message

```sh
Conflux client

Usage: conflux [OPTIONS] [COMMAND]

Commands:
  account  Manage accounts
  dump     Dump eSpace account state at a given block number
  rpc      RPC based subcommands to query blockchain information and send transactions
  help     Print this message or the help of the given subcommand(s)

Options:
      --mode <MODE>
          Use the preset testing configurations. dev or test
  -p, --port <PORT>
          Specify the port for P2P connections
  ...
```

Each command-line tool comes with its own help information. Users can view the help message by using the -h or --help flag.
For example, to view the help information for the account command

```sh
./conflux account -h

conflux-account 
Manage accounts

USAGE:
    conflux account <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help      Prints this message or the help of the given subcommand(s)
    import    Import accounts from JSON UTC keystore files to the specified --chain (default conflux)
    list      List existing accounts of the given --chain (default conflux).
    new       Create a new account (and its associated key) for the given --chain (default conflux).
```

## dump subcommand

This command can be used to export all account states at a certain block height in eSpace to JSON files, facilitating development and debugging. The exported data structure example is as follows

```sh
$ ./conflux --config devnode.toml dump --block 1000 # export state at height 1000
{
  "root": "0xdd606752e465cb6a1e2f0df718057536ab00cd66d9c6fa46085309145823d3c0",
  "accounts": {
    "0x004e322e7ea7e63547d25639d8e8ed282318eec9": {
      "balance": "0x152cfd9872b245dcbcae",
      "nonce": 210,
      "root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
      "codeHash": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
      "address": "0x004e322e7ea7e63547d25639d8e8ed282318eec9",
      "key": "0x0c1bad9586421be5b0d8eda4446cac4ce7692d67301d07146a87455e7bc9d30e"
    },
    "0x0c80d6926edc73977dce4c97ff8966abf04fe80e": {
      "balance": "0x0",
      "nonce": 2,
      "root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
      "codeHash": "0xe79d1e04e3004c8d97ad51f5f08cfd1a79e6cdcce2a3a6d59676a9858bccd173",
      "code": "0xf90338b903206080604052600436106100385760003.....",
      "storage": {
        "0x0000000000000000000000000000000000000000000000000000000000000000": "0xc",
        "0x0000000000000000000000000000000000000000000000000000000000000001": "0x27e26b9234ec81a0247a6083edf8b329fb1ccde9"
      },
      "address": "0x0c80d6926edc73977dce4c97ff8966abf04fe80e",
      "key": "0x691460d9548cee180ba8cd9f0960fee74fed16501d80cdb3182aa0f41b160e54"
    }
  }
}
```

Note: 

1. Conflux contract data storage differs significantly from Ethereum, as it is not stored in separate MPT form, therefore the storage root cannot be obtained. The exported data's `account.root` is fixed as `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`
2. The exported root information is the full state root of Conflux dual-space (Core Space, eSpace), only for maintaining data format consistency, not the state root of all eSpace accounts.
3. When exporting mainnet state data, due to the large number of accounts, high machine configuration is required, and the runtime will be quite long; if you want to export the state at a certain height in history, it needs to be performed on a fullstate node data.
4. When performing state export, please stop the node program first, then execute the export operation in the node directory.
5. Please use the binary corresponding to the network and execute the export operation in the corresponding network data directory; do not use testnet or master code compiled binary to execute export operations on mainnet data.