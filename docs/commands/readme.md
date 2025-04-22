# commands

conflux binary 除了主要作为 Conflux 网络的节点运行程序外，还提供了一些命令行工具，方便用户进行一些操作。

目前包含的子命令有：

- `account`：管理账户
- `evm`：EVM 相关的子命令, 例如运行 statetest 等
- `rpc`：基于 RPC 的子命令，用于查询区块链信息和发送交易
- `help`：打印帮助信息

```sh
./conflux -h
conflux conflux-rust/v2.4.0-82500ad-20250418/x86_64-linux-gnu/rustc1.77.2
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
    evm        EVM related subcommands
    help       Prints this message or the help of the given subcommand(s)
    rpc        RPC based subcommands to query blockchain information and send transactions
```

每个命令行工具都有自己的帮助信息，用户可以通过 `-h` 或 `--help` 参数查看帮助信息。
例如，查看 `account` 命令的帮助信息：

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