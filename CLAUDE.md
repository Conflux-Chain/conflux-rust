# Conflux-Rust Development Guide

## 1. Project Overview

Conflux-Rust is a Rust implementation of the Conflux protocol, a high-performance and reliable blockchain node software.

- **MSRV**: Rust 1.94
- **License**: GNU General Public License v3.0
- **Repository**: https://github.com/Conflux-Chain/conflux-rust

## 2. Architecture Overview

### Directory Structure

```
conflux-rust/
├── bins/                    # Executable programs
│   ├── conflux/            # Main node program and CLI tool
│   ├── cfx_store/          # Account management tool
│   └── cfx_key/            # Key generation tool
├── crates/                  # Core code libraries
│   ├── accounts/           # Account management
│   ├── blockgen/           # Block generation
│   ├── cfx_addr/           # Conflux Base32 address encoding/decoding
│   ├── cfx_bytes/          # Byte manipulation utilities
│   ├── cfxcore/            # Conflux protocol core implementation
│   │   ├── core/           # Consensus, transaction pool, and core logic
│   │   ├── pow/            # PoW implementation
│   │   └── types/          # Core type definitions
│   ├── cfx_crypto/         # Cryptographic primitives (secp256k1, AES, HMAC, scrypt, etc.)
│   ├── cfx_key/            # Key generation tool
│   ├── cfx_store/          # Key storage management
│   ├── cfx_types/          # Blockchain base types (Address, U256, H256, etc.)
│   ├── client/             # Client startup logic
│   ├── config/             # Node configuration management
│   ├── dbs/                # Database layer
│   │   ├── storage/        # State storage (MPT)
│   │   ├── statedb/        # State database wrapper
│   │   ├── db/             # Database open/management
│   │   ├── db-errors/      # Database error definitions
│   │   └── kvdb-rocksdb/   # RocksDB Rust wrapper
│   ├── eest_types/         # Ethereum Execution Spec Test types
│   ├── execution/          # Transaction execution engine
│   │   ├── executor/       # EVM executor
│   │   ├── vm-interpreter/  # VM interpreter
│   │   ├── vm-types/       # VM type definitions
│   │   ├── solidity-abi/    # Solidity ABI handling
│   │   ├── execute-helper/  # Execution helper utilities
│   │   ├── geth-tracer/    # Geth-style tracer implementation
│   │   └── parity-trace-types/ # Parity-style tracer type definitions
│   ├── network/            # P2P network implementation
│   ├── parameters/         # Conflux core parameter constants
│   ├── pos/                # PoS related implementation
│   │   ├── consensus/      # PoS consensus
│   │   ├── crypto/         # PoS cryptography
│   │   ├── storage/        # PoS storage
│   │   ├── secure/         # PoS security module
│   │   └── types/          # PoS type definitions
│   ├── primitives/         # Core data structures (Block, Transaction, Receipt)
│   ├── rpc/                # RPC implementation (jsonrpsee)
│   │   ├── rpc-eth-api/    # eSpace RPC interface definitions
│   │   ├── rpc-eth-impl/   # eSpace RPC implementation
│   │   ├── rpc-cfx-api/    # Core Space RPC interface definitions
│   │   ├── rpc-cfx-impl/   # Core Space RPC implementation
│   │   ├── rpc-eth-types/  # eSpace RPC types
│   │   ├── rpc-cfx-types/  # Core Space RPC types
│   │   ├── rpc-builder/    # RPC service builder
│   │   ├── rpc-primitives/ # RPC primitive types
│   │   ├── rpc-utils/      # RPC common utilities
│   │   ├── rpc-middlewares/ # RPC middlewares
│   │   └── rpc-common-impl/ # RPC common implementation
│   ├── secret_store/       # Key management library
│   ├── stratum/            # PoW mining Stratum protocol
│   ├── tasks/              # Task management (async task wrapper)
│   ├── transactiongen/      # Transaction generation
│   └── util/               # Common utility library
│       ├── metrics/        # Metrics collection
│       ├── io/             # IO utilities
│       ├── cfx_math/       # Math operations
│       ├── memory-cache/   # Memory cache
│       ├── heap-map/       # Heap map
│       ├── treap-map/       # Treap map
│       ├── hibitset/       # Efficient bitset
│       ├── dag/            # DAG structure
│       ├── throttling/     # Rate limiting
│       └── ...
├── internal_contract/      # Internal contract ABI
├── tests/                  # Python integration tests (legacy)
├── integration_tests/      # Python integration tests (pytest)
├── docs/                   # Documentation
├── dev-support/            # Development support scripts
├── run/                    # Runtime configuration and scripts
└── tools/                  # Standalone tools (benchmark, evm-spec-tester, etc.)

```

### Key Crate Reference

| Crate | Description |
|-------|-------------|
| `cfxcore/core` | Consensus engine, transaction pool, block management |
| `execution/executor` | EVM transaction executor |
| `dbs/storage` | MPT state storage |
| `network` | P2P network communication |
| `client` | client startup |
| `rpc/rpc-eth-*` | eSpace RPC (using jsonrpsee) |
| `pos/*` | PoS consensus, cryptography, storage |
| `cfx_types` | Blockchain common types (Address, U256, H256) |
| `cfx_crypto` | Cryptographic primitives (secp256k1, AES, HMAC, scrypt) |
| `primitives` | Core data structures (Block, Transaction, Receipt) |
| `config` | Node configuration management |
| `stratum` | PoW mining Stratum protocol |
| `transactiongen` | Transaction generation |
| `accounts` | Account management |
| `cfx_addr` | Conflux Base32 address encoding/decoding |
| `tasks` | Async task management wrapper |

## 3. Code Style and Formatting

### Formatting Commands

```bash
# Format code (requires installing toolchain first)
./cargo_fmt.sh --install  # Install formatting tools
./cargo_fmt.sh            # Format all code

# Use nightly-2025-02-01 toolchain
dev-support/cargo_all.sh +nightly-2025-02-01 fmt --all
```

### Rustfmt Configuration

- Edition: 2021
- Max width: 80
- Tab spaces: 4
- Import sorting: `Crate` level
- See `rustfmt.toml` for more configuration

### Code Checks

```bash
# Clippy checks
cargo clippy --all
```

## 4. Common Commands

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# MacOS bz2 dependency fix
RUSTFLAGS="-L $(brew --prefix bzip2)/lib -l bz2" cargo build

# Linux with clang
CC=clang CXX=clang++ cargo build --release

# Clean and rebuild
cargo clean && cargo update
```

### Testing

```bash
# Unit tests
cargo test --release --all

# Run tests for specific crate
cargo test -p cfxcore

# Integration tests (Python)
source ./dev-support/activate_new_venv.sh
bash ./dev-support/dep_pip3.sh
cargo build --release
cd tools/consensus_bench && cargo build --release && cd ../..
git submodule update --remote --recursive --init

# Run integration tests
python3 tests/test_all.py                                    # tests/ directory
pytest ./integration_tests/tests -vv -n 6 --dist loadscope   # integration_tests/ directory
```

### Running Node

```bash
# Start mainnet node
./target/release/conflux

# Show help
./target/release/conflux --help
```

### Common Development Commands

```bash
# Check code compiles (no binary generation)
cargo check --all

# View dependency tree
cargo tree

# Generate documentation
cargo doc --no-deps

# Production build
cargo build --release
```
