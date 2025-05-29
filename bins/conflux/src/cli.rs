use clap::{Args, Parser, Subcommand, ValueEnum};

/// Conflux client
#[derive(Parser, Debug)]
#[clap(
    name = "conflux",
    about = "Conflux client",
    author = "The Conflux Team",
    version
)]
pub struct Cli {
    /// Use the preset testing configurations. dev or test.
    #[arg(long, value_name = "MODE", value_enum)]
    pub mode: Option<String>,

    /// Specify the port for P2P connections.
    #[arg(long, short = 'p', value_name = "PORT")]
    pub port: Option<String>,

    /// Specify the UDP port for peer discovery.
    #[arg(id = "udp-port", long = "udp-port", value_name = "PORT")]
    pub udp_port: Option<String>,

    /// Specify the port for the WebSocket JSON-RPC API server.
    #[arg(
        id = "jsonrpc-ws-port",
        long = "jsonrpc-ws-port",
        value_name = "PORT"
    )]
    pub jsonrpc_ws_port: Option<String>,

    /// Specify the port for the TCP JSON-RPC API server.
    #[arg(
        id = "jsonrpc-tcp-port",
        long = "jsonrpc-tcp-port",
        value_name = "PORT"
    )]
    pub jsonrpc_tcp_port: Option<String>,

    /// Specify the port for the HTTP JSON-RPC API server.
    #[arg(
        id = "jsonrpc-http-port",
        long = "jsonrpc-http-port",
        value_name = "PORT"
    )]
    pub jsonrpc_http_port: Option<String>,

    /// Specify CORS header for HTTP JSON-RPC API responses.
    #[arg(id = "jsonrpc-cors", long = "jsonrpc-cors", value_name = "URL")]
    pub jsonrpc_cors: Option<String>,

    /// Enable HTTP/1.1 keep alive header.
    #[arg(
        id = "jsonrpc-http-keep-alive",
        long = "jsonrpc-http-keep-alive",
        value_name = "BOOL"
    )]
    pub jsonrpc_http_keep_alive: Option<String>,

    /// Specify the filename for the log. Stdout will be used by default if
    /// omitted.
    #[arg(id = "log-file", long = "log-file", value_name = "FILE")]
    pub log_file: Option<String>,

    /// Can be error/warn/info/debug/trace. Default is the info level.
    #[arg(id = "log-level", long = "log-level", value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Sets a custom log config file.
    #[arg(id = "log-conf", long = "log-conf", value_name = "FILE")]
    pub log_conf: Option<String>,

    /// Sets a custom config file.
    #[arg(short = 'c', long, value_name = "FILE")]
    pub config: Option<String>,

    /// Sets a custom list of bootnodes.
    #[arg(long, value_name = "NODES")]
    // "bootnodes" does not contain a hyphen
    pub bootnodes: Option<String>,

    /// Sets a custom directory for network configurations.
    #[arg(id = "netconf-dir", long = "netconf-dir", value_name = "DIR")]
    pub netconf_dir: Option<String>,

    /// Sets a custom public address to be connected by others.
    #[arg(
        id = "public-address",
        long = "public-address",
        value_name = "IP ADDRESS"
    )]
    pub public_address: Option<String>,

    /// Sets a custom secret key to generate unique node ID.
    #[arg(id = "net-key", long = "net-key", value_name = "KEY")]
    pub net_key: Option<String>,

    /// Start mining if set to true. Ensure that mining-author is set.
    #[arg(id = "start-mining", long = "start-mining", value_name = "BOOL")]
    pub start_mining: Option<String>,

    /// Set the address to receive mining rewards.
    #[arg(
        id = "mining-author",
        long = "mining-author",
        value_name = "ADDRESS"
    )]
    pub mining_author: Option<String>,

    /// Sets the ledger cache size.
    #[arg(
        id = "ledger-cache-size",
        long = "ledger-cache-size",
        value_name = "SIZE"
    )]
    pub ledger_cache_size: Option<String>,

    /// Sets the db cache size.
    #[arg(id = "db-cache-size", long = "db-cache-size", value_name = "SIZE")]
    pub db_cache_size: Option<String>,

    /// Enable discovery protocol.
    #[arg(
        id = "enable-discovery",
        long = "enable-discovery",
        value_name = "BOOL"
    )]
    pub enable_discovery: Option<String>,

    /// How often Conflux updates its peer table (default 300).
    #[arg(
        id = "node-table-timeout-s",
        long = "node-table-timeout-s",
        value_name = "SEC"
    )]
    pub node_table_timeout_s: Option<String>,

    /// How long Conflux waits for promoting a peer to trustworthy (default 3 *
    /// 24 * 3600).
    #[arg(
        id = "node-table-promotion-timeout-s",
        long = "node-table-promotion-timeout-s",
        value_name = "SEC"
    )]
    pub node_table_promotion_timeout_s: Option<String>,

    /// Sets test mode for adding latency
    #[arg(id = "test-mode", long = "test-mode", value_name = "BOOL")]
    pub test_mode: Option<String>,

    /// Sets the compaction profile of RocksDB.
    #[arg(
        id = "db-compact-profile",
        long = "db-compact-profile",
        value_name = "ENUM"
    )]
    pub db_compact_profile: Option<String>,

    /// Sets the root path of db.
    #[arg(id = "block-db-dir", long = "block-db-dir", value_name = "DIR")]
    pub block_db_dir: Option<String>,

    /// Sets the test chain json file.
    #[arg(
        id = "load-test-chain",
        long = "load-test-chain",
        value_name = "FILE"
    )]
    pub load_test_chain: Option<String>,

    /// Sets egress queue capacity of P2P network.
    #[arg(
        id = "egress-queue-capacity",
        long = "egress-queue-capacity",
        value_name = "MB"
    )]
    pub egress_queue_capacity: Option<String>,

    /// Sets minimum throttling queue size of egress.
    #[arg(
        id = "egress-min-throttle",
        long = "egress-min-throttle",
        value_name = "MB"
    )]
    pub egress_min_throttle: Option<String>,

    /// Sets maximum throttling queue size of egress.
    #[arg(
        id = "egress-max-throttle",
        long = "egress-max-throttle",
        value_name = "MB"
    )]
    pub egress_max_throttle: Option<String>,

    /// Sets the size of the epoch batches used during log filtering.
    #[arg(
        id = "get-logs-epoch-batch-size",
        long = "get-logs-epoch-batch-size",
        value_name = "SIZE"
    )]
    pub get_logs_epoch_batch_size: Option<String>,

    /// Sets the maximum number of allowed epochs during log filtering.
    #[arg(
        id = "get-logs-filter-max-epoch-range",
        long = "get-logs-filter-max-epoch-range",
        value_name = "SIZE"
    )]
    pub get_logs_filter_max_epoch_range: Option<String>,

    /// Sets the maximum number of log entries returned during log filtering.
    #[arg(
        id = "get-logs-filter-max-limit",
        long = "get-logs-filter-max-limit",
        value_name = "SIZE"
    )]
    pub get_logs_filter_max_limit: Option<String>,

    /// Sets the maximum number of allowed blocks during log filtering.
    #[arg(
        id = "get-logs-filter-max-block-number-range",
        long = "get-logs-filter-max-block-number-range",
        value_name = "SIZE"
    )]
    pub get_logs_filter_max_block_number_range: Option<String>,

    /// Sets the time after which accounts are re-read from disk.
    #[arg(
        id = "account-provider-refresh-time-ms",
        long = "account-provider-refresh-time-ms",
        value_name = "MS"
    )]
    pub account_provider_refresh_time_ms: Option<String>,

    ///  Sets the encryption password for the pos private key file. It's used
    /// to encrypt a new generated key or to decrypt an existing key file.
    #[arg(
        id = "dev-pos-private-key-encryption-password",
        long = "dev-pos-private-key-encryption-password",
        value_name = "PASSWD"
    )]
    pub dev_pos_private_key_encryption_password: Option<String>,

    /// If true, the node will start PoS election and voting if it's available.
    #[arg(
        id = "pos-started-as-voter",
        long = "pos-started-as-voter",
        value_name = "BOOL"
    )]
    pub pos_started_as_voter: Option<String>,

    #[arg(long)]
    pub light: bool,
    #[arg(long)]
    pub archive: bool,
    #[arg(long)]
    pub tg_archive: bool,
    #[arg(long)]
    pub full: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage accounts
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Account(AccountSubcommands),
    /// RPC based subcommands to query blockchain information and send
    /// transactions
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Rpc(RpcCommand),
}

/**
 * --------------- Account Subcommands ---------------
 */

/// Account Subcommands
#[derive(Args, Debug)]
pub struct AccountSubcommands {
    #[command(subcommand)]
    pub command: AccountCommand,
}

#[derive(Subcommand, Debug)]
pub enum AccountCommand {
    /// Create a new account (and its associated key) for the given --chain
    /// (default conflux).
    New(AccountNewArgs),
    /// List existing accounts of the given --chain (default conflux).
    List,
    /// Import accounts from JSON UTC keystore files
    Import(AccountImportArgs),
}

#[derive(Args, Debug)]
pub struct AccountNewArgs {
    /// Specify the number of iterations to use when deriving key from the
    /// password (bigger is more secure).
    #[arg(
        id = "keys-iterations",
        long = "keys-iterations",
        value_name = "NUM",
        default_value = "10240"
    )]
    pub keys_iterations: Option<u32>,
    /// Provide a file containing a password for unlocking an account.
    #[arg(long, value_name = "FILE")]
    pub password: Option<String>,
}

#[derive(Args, Debug)]
pub struct AccountImportArgs {
    /// A list of file paths to import.
    #[arg(id = "import-path", long = "import-path", value_name = "PATH", required = true, num_args = 1..)]
    pub import_path: Vec<String>,
}

/**
 * --------------- RPC Subcommands ---------------
 */

// RPC Subcommands
#[derive(Args, Debug)]
pub struct RpcCommand {
    /// URL of RPC server
    #[arg(
        long,
        value_name = "URL",
        default_value = "http://localhost:12539",
        global = true
    )]
    pub url: String,
    #[command(subcommand)]
    pub command: RpcSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum RpcSubcommands {
    /// Get recent mean gas price
    Price(RpcPriceArgs),
    /// Get epoch number
    Epoch(RpcEpochArgs),
    /// Get balance of specified account
    Balance(RpcBalanceArgs),
    /// Get bytecode of specified contract
    Code(RpcCodeArgs),
    /// Get block by hash
    #[command(name = "block-by-hash")]
    BlockByHash(RpcBlockByHashArgs),
    /// Get block by hash with pivot chain assumption
    #[command(name = "block-with-assumption")]
    BlockWithAssumption(RpcBlockWithAssumptionArgs),
    /// Get block by epoch
    #[command(name = "block-by-epoch")]
    BlockByEpoch(RpcBlockByEpochArgs),
    /// Get the best block hash
    #[command(name = "best-block-hash")]
    BestBlockHash(RpcBestBlockHashArgs),
    /// Get nonce of specified account
    Nonce(RpcNonceArgs),
    /// Send a signed transaction and return its hash
    Send(RpcSendArgs),
    /// Get transaction by hash
    Tx(RpcTxArgs),
    /// Get blocks of specified epoch
    Blocks(RpcBlocksArgs),
    /// Get skipped blocks of specified epoch
    #[command(name = "skipped-blocks")]
    SkippedBlocks(RpcSkippedBlocksArgs),
    /// Get receipt by transaction hash
    Receipt(RpcReceiptArgs),
    /// Executes a new message call immediately without creating a transaction
    Call(RpcCallArgs),
    /// Executes a call request and returns the gas used
    #[command(name = "estimate-gas")]
    EstimateGas(RpcEstimateGasArgs),
    /// Local subcommands (requires jsonrpc_local_http_port configured)
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Local(RpcLocalSubcommands),
}

#[derive(Args, Debug)]
pub struct RpcPriceArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_gasPrice",
        hide = true
    )]
    pub rpc_method: String,
}

#[derive(Args, Debug)]
pub struct RpcEpochArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_epochNumber",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "epoch",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Epoch (latest_mined, latest_state, earliest or epoch number in HEX
    /// format)
    #[arg(long, value_name = "EPOCH")]
    pub epoch: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcBalanceArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_getBalance",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "address,epoch",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Account address / Contract address
    #[arg(long, required = true, value_name = "ADDRESS")]
    pub address: String,
    /// Epoch (latest_mined, latest_state, earliest or epoch number in HEX
    /// format)
    #[arg(long, value_name = "EPOCH")]
    pub epoch: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcCodeArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_getCode",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "address,epoch",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    #[arg(long = "address", required = true, value_name = "ADDRESS")]
    pub address: String,
    /// Epoch (latest_mined, latest_state, earliest or epoch number in HEX
    /// format)
    #[arg(long, required = true, value_name = "EPOCH")]
    pub epoch: String,
}

#[derive(Args, Debug)]
pub struct RpcBlockByHashArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_getBlockByHash",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "hash,include-txs:bool",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Block hash / Transaction hash
    #[arg(long, required = true, value_name = "HASH")]
    pub hash: String,
    /// Whether to return detailed transactions in block
    #[arg(id = "include-txs", long = "include-txs")]
    pub include_txs: bool,
}

#[derive(Args, Debug)]
pub struct RpcBlockWithAssumptionArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_getBlockByHashWithPivotAssumption",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "block-hash,pivot-hash,epoch-number:u64",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Block hash
    #[arg(
        id = "block-hash",
        long = "block-hash",
        required = true,
        value_name = "HASH"
    )]
    pub block_hash: String,
    /// Pivot block hash
    #[arg(
        id = "pivot-hash",
        long = "pivot-hash",
        required = true,
        value_name = "HASH"
    )]
    pub pivot_hash: String,
    /// Epoch number
    #[arg(
        id = "epoch-number",
        long = "epoch-number",
        required = true,
        value_name = "NUMBER"
    )]
    pub epoch_number: u64,
}

#[derive(Args, Debug)]
pub struct RpcBlockByEpochArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_getBlockByEpochNumber",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "epoch,include-txs:bool",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Epoch (latest_mined, latest_state, earliest or epoch number in HEX
    /// format)
    #[arg(long, required = true, value_name = "EPOCH")]
    pub epoch: String,
    /// Whether to return detailed transactions in block
    #[arg(id = "include-txs", long = "include-txs")]
    pub include_txs: bool,
}

#[derive(Args, Debug)]
pub struct RpcBestBlockHashArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_getBestBlockHash",
        hide = true
    )]
    pub rpc_method: String,
}

#[derive(Args, Debug)]
pub struct RpcNonceArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_getNextNonce",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "address,epoch",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Account address / Contract address
    #[arg(long, required = true, value_name = "ADDRESS")]
    pub address: String,
    /// Epoch (latest_mined, latest_state, earliest or epoch number in HEX
    /// format)
    #[arg(long, value_name = "EPOCH")]
    pub epoch: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcSendArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_sendRawTransaction",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "raw-bytes",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Signed transaction data
    #[arg(
        id = "raw-bytes",
        long = "raw-bytes",
        required = true,
        value_name = "HEX"
    )]
    pub raw_bytes: String,
}

#[derive(Args, Debug)]
pub struct RpcTxArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_getTransactionByHash",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "hash",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Block hash / Transaction hash
    #[arg(long, required = true, value_name = "HASH")]
    pub hash: String,
}

#[derive(Args, Debug)]
pub struct RpcBlocksArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_getBlocksByEpoch",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "epoch",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Epoch (latest_mined, latest_state, earliest or epoch number in HEX
    /// format)
    #[arg(long, required = true, value_name = "EPOCH")]
    pub epoch: String,
}

#[derive(Args, Debug)]
pub struct RpcSkippedBlocksArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_getSkippedBlocksByEpoch",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "epoch",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Epoch (latest_mined, latest_state, earliest or epoch number in HEX
    /// format)
    #[arg(long, required = true, value_name = "EPOCH")]
    pub epoch: String,
}

#[derive(Args, Debug)]
pub struct RpcReceiptArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_getTransactionReceipt",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "hash",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Block hash / Transaction hash
    #[arg(long, required = true, value_name = "HASH")]
    pub hash: String,
}

#[derive(Args, Debug)]
pub struct RpcCallArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_call",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "tx:map(from;to;gas-price;type;max-fee-per-gas;max-priority-fee-per-gas;gas;value;data;nonce),epoch",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Transaction from address
    #[arg(long, value_name = "ADDRESS")]
    pub from: Option<String>,
    /// Transaction to address
    #[arg(long, value_name = "ADDRESS")]
    pub to: Option<String>,
    /// Transaction gas price
    #[arg(id = "gas-price", long = "gas-price", value_name = "HEX")]
    pub gas_price: Option<String>,
    /// Transaction type
    #[arg(id = "type", long = "type", value_name = "HEX")]
    // "type" does not contain a hyphen
    pub tx_type: Option<String>,
    /// Transaction max fee per gas
    #[arg(
        id = "max-fee-per-gas",
        long = "max-fee-per-gas",
        value_name = "HEX"
    )]
    pub max_fee_per_gas: Option<String>,
    /// Transaction max priority fee per gas
    #[arg(
        id = "max-priority-fee-per-gas",
        long = "max-priority-fee-per-gas",
        value_name = "HEX"
    )]
    pub max_priority_fee_per_gas: Option<String>,
    /// Gas provided for transaction execution
    #[arg(long, value_name = "HEX")]
    pub gas: Option<String>,
    /// value sent with this transaction
    #[arg(long, value_name = "HEX")]
    pub value: Option<String>,
    /// Hash of the method signature and encoded parameters
    #[arg(long, value_name = "HEX")]
    pub data: Option<String>,
    /// Transaction nonce
    #[arg(long, value_name = "HEX")]
    pub nonce: Option<String>,
    /// Epoch
    #[arg(long, value_name = "EPOCH")]
    pub epoch: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcEstimateGasArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_estimateGas",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "tx:map(from;to;gas-price;type;max-fee-per-gas;max-priority-fee-per-gas;gas;value;data;nonce),epoch",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Transaction from address
    #[arg(long, value_name = "ADDRESS")]
    pub from: Option<String>,
    /// Transaction to address
    #[arg(long, value_name = "ADDRESS")]
    pub to: Option<String>,
    /// Transaction gas price
    #[arg(id = "gas-price", long = "gas-price", value_name = "HEX")]
    pub gas_price: Option<String>,
    /// Transaction type
    #[arg(id = "type", long = "type", value_name = "HEX")]
    // "type" does not contain a hyphen
    pub tx_type: Option<String>,
    /// Transaction max fee per gas
    #[arg(
        id = "max-fee-per-gas",
        long = "max-fee-per-gas",
        value_name = "HEX"
    )]
    pub max_fee_per_gas: Option<String>,
    /// Transaction max priority fee per gas
    #[arg(
        id = "max-priority-fee-per-gas",
        long = "max-priority-fee-per-gas",
        value_name = "HEX"
    )]
    pub max_priority_fee_per_gas: Option<String>,
    /// Gas provided for transaction execution
    #[arg(long, value_name = "HEX")]
    pub gas: Option<String>,
    /// value sent with this transaction
    #[arg(long, value_name = "HEX")]
    pub value: Option<String>,
    /// Hash of the method signature and encoded parameters
    #[arg(long, value_name = "HEX")]
    pub data: Option<String>,
    /// Transaction nonce
    #[arg(long, value_name = "HEX")]
    pub nonce: Option<String>,
    /// Epoch
    #[arg(long, value_name = "EPOCH")]
    pub epoch: Option<String>,
}

/**
 * --------------- RPC Local Subcommands ---------------
 */

// RPC Local Subcommands
#[derive(Args, Debug)]
pub struct RpcLocalSubcommands {
    #[command(subcommand)]
    pub command: RpcLocalCommand,
}

#[derive(Subcommand, Debug)]
pub enum RpcLocalCommand {
    /// Send a transaction and return its hash
    Send(RpcLocalSendArgs),
    /// Account related subcommands
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Account(RpcLocalAccountSubcommands),
    /// Transaction pool subcommands
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Txpool(RpcLocalTxpoolSubcommands),
    /// Network subcommands
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Net(RpcLocalNetSubcommands),
    /// Get the current synchronization phase
    #[command(name = "sync-phase")]
    SyncPhase(RpcLocalSyncPhaseArgs),
    /// Get the consensus graph state
    #[command(name = "consensus-graph-state")]
    ConsensusGraphState(RpcLocalConsensusGraphStateArgs),
    /// Test subcommands (used for test purpose only)
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Test(RpcLocalTestSubcommands),
    /// PoS subcommands
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Pos(RpcLocalPosSubcommands),
}

#[derive(Args, Debug)]
pub struct RpcLocalSendArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_sendTransaction",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "tx:map(from;to;gas-price;type;max-fee-per-gas;max-priority-fee-per-gas;gas;value;data;nonce;storageLimit),password:password",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Transaction from address
    #[arg(long, required = true, value_name = "ADDRESS")]
    pub from: String,
    /// Transaction to address (empty to create contract)
    #[arg(long, value_name = "ADDRESS")]
    pub to: Option<String>,
    /// Transaction gas price
    #[arg(
        id = "gas-price",
        long = "gas-price",
        value_name = "HEX",
        default_value = "0x2540BE400"
    )]
    pub gas_price: Option<String>,
    /// Transaction type
    #[arg(id = "type", long = "type", value_name = "HEX")]
    // "type" does not contain a hyphen
    pub tx_type: Option<String>,
    /// Transaction max fee per gas
    #[arg(
        id = "max-fee-per-gas",
        long = "max-fee-per-gas",
        value_name = "HEX"
    )]
    pub max_fee_per_gas: Option<String>,
    /// Transaction max priority fee per gas
    #[arg(
        id = "max-priority-fee-per-gas",
        long = "max-priority-fee-per-gas",
        value_name = "HEX"
    )]
    pub max_priority_fee_per_gas: Option<String>,
    /// Gas provided for transaction execution
    #[arg(long, value_name = "HEX", default_value = "0x5208")]
    pub gas: Option<String>,
    /// value sent with this transaction
    #[arg(long, required = true, value_name = "HEX")]
    pub value: String,
    /// Hash of the method signature and encoded parameters
    #[arg(long, value_name = "HEX")]
    pub data: Option<String>,
    /// Transaction nonce
    #[arg(long, value_name = "HEX")]
    pub nonce: Option<String>,
    /// Storage limit for the transaction
    #[arg(
        id = "storage-limit",
        long = "storage-limit",
        value_name = "HEX",
        default_value = "0x0"
    )]
    pub storage_limit: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcLocalAccountSubcommands {
    #[command(subcommand)]
    pub command: RpcLocalAccountCommand,
}

#[derive(Subcommand, Debug)]
pub enum RpcLocalAccountCommand {
    /// List all accounts
    List(RpcLocalAccountListArgs),
    /// Create a new account
    New(RpcLocalAccountNewArgs),
    /// Unlock an account
    Unlock(RpcLocalAccountUnlockArgs),
    /// Lock an unlocked account
    Lock(RpcLocalAccountLockArgs),
}

#[derive(Args, Debug)]
pub struct RpcLocalAccountListArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_accounts",
        hide = true
    )]
    pub rpc_method: String,
}

#[derive(Args, Debug)]
pub struct RpcLocalAccountNewArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_newAccount",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "password:password2",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
}

#[derive(Args, Debug)]
pub struct RpcLocalAccountUnlockArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_unlockAccount",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "address,password:password,duration",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Address of the account
    #[arg(long, required = true, value_name = "ADDRESS")]
    pub address: String,
    /// Duration to unlock the account, use 0x0 to unlock permanently (strongly
    /// not recommended!).
    #[arg(long, value_name = "DURATION", default_value = "0x3c")]
    pub duration: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcLocalAccountLockArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_lockAccount",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "address",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Address of the account
    #[arg(long, required = true, value_name = "ADDRESS")]
    pub address: String,
}

#[derive(Args, Debug)]
pub struct RpcLocalTxpoolSubcommands {
    #[command(subcommand)]
    pub command: RpcLocalTxpoolCommand,
}

#[derive(Subcommand, Debug)]
pub enum RpcLocalTxpoolCommand {
    /// Get the number of transactions for different status
    Status(RpcLocalTxpoolStatusArgs),
    /// Get the detailed status of specified transaction
    #[command(name = "inspect-one")]
    InspectOne(RpcLocalTxpoolInspectOneArgs),
    /// List textual summary of all transactions
    Inspect(RpcLocalTxpoolInspectArgs),
    /// List exact details of all transactions
    Content(RpcLocalTxpoolContentArgs),
    /// Remove all transactions
    Clear(RpcLocalTxpoolClearArgs),
}

#[derive(Args, Debug)]
pub struct RpcLocalTxpoolStatusArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "txpool_status",
        hide = true
    )]
    pub rpc_method: String,
}

#[derive(Args, Debug)]
pub struct RpcLocalTxpoolInspectOneArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "txpool_txWithPoolInfo",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "hash",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Block hash / Transaction hash
    #[arg(long, required = true, value_name = "HASH")]
    pub hash: String,
}

#[derive(Args, Debug)]
pub struct RpcLocalTxpoolInspectArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "debug_inspectTxPool",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "address",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Account address
    #[arg(long, value_name = "ADDRESS")]
    pub address: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcLocalTxpoolContentArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "debug_txPoolContent",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "address",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Account address
    #[arg(long, value_name = "ADDRESS")]
    pub address: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcLocalTxpoolClearArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "debug_clearTxPool",
        hide = true
    )]
    pub rpc_method: String,
}

#[derive(Args, Debug)]
pub struct RpcLocalNetSubcommands {
    #[command(subcommand)]
    pub command: RpcLocalNetCommand,
}

#[derive(Subcommand, Debug)]
pub enum RpcLocalNetCommand {
    /// Get the current throttling information
    Throttling(RpcLocalNetThrottlingArgs),
    /// Get node information by ID
    Node(RpcLocalNetNodeArgs),
    /// Disconnect a node
    Disconnect(RpcLocalNetDisconnectArgs),
    /// Get active session(s)
    Session(RpcLocalNetSessionArgs),
}

#[derive(Args, Debug)]
pub struct RpcLocalNetThrottlingArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "debug_getNetThrottling",
        hide = true
    )]
    pub rpc_method: String,
}

#[derive(Args, Debug)]
pub struct RpcLocalNetNodeArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "debug_getNetNode",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "id",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Node ID
    #[arg(long, required = true, value_name = "ID")]
    pub id: String,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum NodeDisconnectOperation {
    Failure,
    Demotion,
    Remove,
}

#[derive(Args, Debug)]
pub struct RpcLocalNetDisconnectArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "debug_disconnectNetNode",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "id,operation",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Node ID
    #[arg(long, required = true, value_name = "ID")]
    pub id: String,
    /// Operation to update node database
    #[arg(long, value_name = "OPERATION", value_enum)]
    pub operation: Option<NodeDisconnectOperation>,
}

#[derive(Args, Debug)]
pub struct RpcLocalNetSessionArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "debug_getNetSessions",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "id",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// Node ID
    #[arg(long, value_name = "ID")]
    pub id: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcLocalSyncPhaseArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "debug_currentSyncPhase",
        hide = true
    )]
    pub rpc_method: String,
}

#[derive(Args, Debug)]
pub struct RpcLocalConsensusGraphStateArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "debug_consensusGraphState",
        hide = true
    )]
    pub rpc_method: String,
}

#[derive(Args, Debug)]
pub struct RpcLocalTestSubcommands {
    #[command(subcommand)]
    pub command: RpcLocalTestCommand,
}

#[derive(Subcommand, Debug)]
pub enum RpcLocalTestCommand {
    /// Get the total block count
    #[command(name = "block-count")]
    BlockCount(RpcLocalTestBlockCountArgs),
    /// Get the recent transaction good TPS
    Goodput(RpcLocalTestGoodputArgs),
    /// List "ALL" blocks in topological order
    Chain(RpcLocalTestChainArgs),
    /// Stop the conflux program
    Stop(RpcLocalTestStopArgs),
    /// Get the current status of Conflux
    Status(RpcLocalTestStatusArgs),
}

#[derive(Args, Debug)]
pub struct RpcLocalTestBlockCountArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "test_getBlockCount",
        hide = true
    )]
    pub rpc_method: String,
}
#[derive(Args, Debug)]
pub struct RpcLocalTestGoodputArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "test_getGoodPut",
        hide = true
    )]
    pub rpc_method: String,
}
#[derive(Args, Debug)]
pub struct RpcLocalTestChainArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "test_getChain",
        hide = true
    )]
    pub rpc_method: String,
}
#[derive(Args, Debug)]
pub struct RpcLocalTestStopArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "test_stop",
        hide = true
    )]
    pub rpc_method: String,
}
#[derive(Args, Debug)]
pub struct RpcLocalTestStatusArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "cfx_getStatus",
        hide = true
    )]
    pub rpc_method: String,
}
#[derive(Args, Debug)]
pub struct RpcLocalPosSubcommands {
    #[command(subcommand)]
    pub command: RpcLocalPosCommand,
}

#[derive(Subcommand, Debug)]
pub enum RpcLocalPosCommand {
    /// Return the transaction data needed to register the PoS keys
    Register(RpcLocalPosRegisterArgs),
    /// Stop sending PoS election transactions.
    #[command(name = "stop_election")]
    StopElection(RpcLocalPosStopElectionArgs),
    /// Start PoS voting.
    #[command(name = "start_voting")]
    StartVoting(RpcLocalPosStartVotingArgs),
    /// Stop PoS voting.
    #[command(name = "stop_voting")]
    StopVoting(RpcLocalPosStopVotingArgs),
    /// Show if the node is voting.
    #[command(name = "voting_status")]
    VotingStatus(RpcLocalPosVotingStatusArgs),
}

#[derive(Args, Debug)]
pub struct RpcLocalPosRegisterArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "test_posRegister",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "power:u64",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// The voting power to register (one voting power is 100 staked CFX)
    #[arg(long, required = true, value_name = "POWER")]
    pub power: u64,
}

#[derive(Args, Debug)]
pub struct RpcLocalPosStopElectionArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "test_posStopElection",
        hide = true
    )]
    pub rpc_method: String,
}

#[derive(Args, Debug)]
pub struct RpcLocalPosStartVotingArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "test_posStartVoting",
        hide = true
    )]
    pub rpc_method: String,
    #[arg(
        id = "rpc-args",
        long = "rpc-args",
        hide = true,
        default_value = "initialize:bool",
        value_delimiter = ','
    )]
    pub rpc_args: Vec<String>,
    /// set this means the node uses its local safety data instead of a saved
    /// data file from another primary node
    #[arg(long)]
    pub initialize: bool,
}

#[derive(Args, Debug)]
pub struct RpcLocalPosStopVotingArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "test_posStopVoting",
        hide = true
    )]
    pub rpc_method: String,
}
#[derive(Args, Debug)]
pub struct RpcLocalPosVotingStatusArgs {
    #[arg(
        id = "rpc-method",
        long = "rpc-method",
        default_value = "test_posVotingStatus",
        hide = true
    )]
    pub rpc_method: String,
}
