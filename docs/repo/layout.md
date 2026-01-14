# Project Layout

This repository contains several Rust crates that implement the different building blocks of a Conflux node. The high-level structure of the repository is as follows:

- [bins](../../bins): All binary crates located in this folder
- [crates](../../crates): All library crates
- [tools](../../tools/): Tools for benchmark, testing (These crates are stand-alone and not included in the whole workspace)
- [internal_contract](../../internal_contract): Internal contracts's abi and interface
- [integration_tests](../../integration_tests) and [tests](../../tests): The python integration tests
- [run](../../run): Node run misc, include default config file and start scripts
- [dev-support](../../dev-support): Dev support scripts
- [docs](../../docs): Documentation
- [changelogs](../../changelogs): Changelogs, especially for the JSON-RPC APIs

## Crates

### binaries

The bins directory contains some binary crates:

- conflux: The conflux binary program, which serves as both the node's startup program and a CLI tool. It can be used for account management, calling RPC interfaces, etc.
- cfx_store: A tool for managing accounts.
- cfx_key: A conflux account key generation tool.
- pos-genesis-tool: A tool for generating PoS genesis data.

### basic crates

- [cfx_bytes](../../crates/cfx_bytes): Provides some general byte manipulation functions.
- [cfx_types](../../crates/cfx_types):Provides some commonly used type definitions in blockchain, such as Address, U256, H256, etc.
- [cfx_addr](../../crates/cfx_addr): Conflux base32 address encoding/decoding.

### primitives

The [primitives crate](../../crates/primitives) contains the core data structures used in the Conflux system. For example, block, transaction, and receipt. This crate forms the foundational data structures of the entire Conflux system.

### cfxcore

The Conflux Protocol's core code located at [cfxcore](../../crates/cfxcore) directory. Including `consensus`, `pow`, `transaction pool` etc.

### execution

The [execution](../../crates/execution) directory contains the execution engine, which is responsible for executing transactions and managing the state of the blockchain. It includes the following core crates:

- [vm-types](../../crates/execution/vm-types/)
- [vm-interpreter](../../crates/execution/vm-interpreter/)
- [executor](../../crates/execution/executor/)
- [execute-helper](../../crates/execution/execute-helper/)

And tracer crates:

- [parity-trace-types](../../crates/execution/parity-trace-types/)
- [geth-tracer](../../crates/execution/geth-tracer/)

Other utility crates:

- [cfx-vm-tracer-derive](../../crates/execution/cfx-vm-tracer-derive/)
- [solidity-abi](../../crates/execution/solidity-abi/)
- [solidity-abi-derive](../../crates/execution/solidity-abi-derive/)

### dbs

All database-related code is located under [dbs](../../crates/dbs), which contains the core logic for the entire node's data storage. Specifically, it mainly includes two major categories of data: blockchain (block header, block body, receipt) and state (state trie, storage trie), as well as some indexing and development data (trace).

The underlying layer primarily uses rocksdb, and also uses sqlite to store some snapshot-related data.

1. kvdb-rocksdb: Rust wrapper for rocksdb, which depends on third-party crates (kvdb, rocksdb) at the underlying layer
2. db: Mainly provides the open_database method, which returns a db instance that can be used for data reading and writing
3. db-errors: Database operation error definitions
4. **storage**: The main implementation of the state database, including mpt, mpt snapshot and other logic, providing lower-level read/write interfaces `StateTrait`. This crate is the core code for state storage
5. statedb: Simple wrapper around storage, providing higher-level read interfaces `StateDbExt`

Additionally, the upper-level modules that call the db module mainly consist of two parts:

1. crates/cfxcore/core/src/block_data_manager: Encapsulates all data read/write interfaces
2. crates/execution/executor/src/state: The state object of the execution module, which essentially wraps StateDb and provides account state reading and updating interfaces for EVM.

### network

The [network](../../crates/network) directory contains the network crate.

### client

The [client](../../crates/client) crate contains the client startup logic and the Core Space RPC implementation.

### RPC

Conflux provides a standard JSON-RPC 2.0 interface to allow external ecosystems (SDKs, wallets, etc.) to interact with the blockchain. Conflux includes two spaces: Core Space and eSpace, each with its own RPC.

The RPC implementation for eSpace is mainly located in the [crates/rpc](../../crates/rpc) directory and is developed using the [jsonrpsee](https://github.com/paritytech/jsonrpsee) RPC framework. It includes multiple crates:

- [rpc-primitives](../../crates/rpc/rpc-primitives/): Definitions of the raw types for RPC.
- [rpc-cfx-types](../../crates/rpc/rpc-cfx-types/): RPC type definitions for Core Space.
- [rpc-eth-types](../../crates/rpc/rpc-eth-types/): RPC type definitions for eSpace.
- [rpc-eth-api](../../crates/rpc/rpc-eth-api/): RPC interface definitions for eSpace, organized by namespace.
- [rpc-eth-impl](../../crates/rpc/rpc-eth-impl/): RPC interface implementation for eSpace.
- [rpc-cfx-impl](../../crates/rpc/rpc-cfx-impl/): RPC interface implementation for Core Space.
- [rpc-builder](../../crates/rpc/rpc-builder/): Logic for RPC interface registration and service startup.
- [rpc-utils](../../crates/rpc/rpc-utils/): Implementation of common utilities, such as error code definitions.

The RPC implementation for Core Space is located in the [crates/client](../../crates/client) crate, developed using [jsonrpc-core](https://github.com/paritytech/jsonrpc)e. The core code is in the src/rpc directory.

### Stratum

Conflux uses the industry-standard `Stratum protocol` for implementing PoW mining. The protocol implementation code is primarily located in the [crates/stratum](../../crates/stratum) and [crates/blockgen](../../crates/blockgen) directories. Additionally, there is some related code in the `crates/cfxcore/core/src/pow/mod.rs` file.

### util

The [util](../../crates/util) directory contains some general utility crates.