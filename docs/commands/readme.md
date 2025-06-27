# commands

In addition to serving as the main node software for running the Conflux network, the conflux binary also provides a set of command-line tools to help users perform various operations more conveniently.

Currently Available Subcommands：

- `account`：Account Management
- `rpc`：RPC-based subcommands, used for querying blockchain information and sending transactions
- `help`：Print help message

```sh
./conflux -h
conflux conflux-rust/v2.4.0-82500ad-20250418/x86_64-linux-gnu/rustc1.78
The Conflux Team
Conflux client.

USAGE:
    conflux [FLAGS] [OPTIONS] [SUBCOMMAND]

FLAGS:
        --archive       
        --full          
    -h, --help          Prints help information
        --light         
        --tg_archive    
    -V, --version       Prints version information

OPTIONS:
    -c, --config <FILE> Sets a custom config file.
    ...
    

SUBCOMMANDS:
    account    Manage accounts
    help       Prints this message or the help of the given subcommand(s)
    rpc        RPC based subcommands to query blockchain information and send transactions
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