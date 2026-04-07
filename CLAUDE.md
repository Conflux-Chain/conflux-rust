# Conflux-Rust Development Guide for AI Agents

This guide provides comprehensive instructions for AI agents working on the Conflux-Rust codebase. It covers the architecture, development workflows, and critical guidelines for effective contributions.

## 1. Project Overview

Conflux-Rust is a Rust implementation of the Conflux protocol, a high-performance and reliable blockchain node software. This project focuses on modularity, performance, and contributor-friendliness. The codebase is organized into well-defined crates with clear boundaries and responsibilities.

## 2. Architecture Overview

1. crates: The main Rust code is located in the `crates` directory, containing core functional modules such as consensus engine, transaction executor, and network communication.
2. bins: Contains executable entry points, such as the `conflux` main node program and other tools (cfx_key, cfx_store).
3. tools: Contains consensus performance testing tools and evm-spec testing tools, etc.
4. integration_tests and tests: The project's integration tests, written in Python. The former uses pytest framework, while the latter uses a blockchain testing framework ported from the Bitcoin client codebase. New test cases should be added to the integration_tests directory; the tests directory is planned for gradual deprecation.
5. docs and changelogs: Project documentation and changelogs, including development guides, design documents, and release notes, etc.
6. internal_contract: Solidity interface code and ABI files for Core Space built-in contracts.
7. dev-support & cargo_fmt.sh: Development support scripts and code formatting tools, including environment setup, dependency installation, and code checking, etc.
8. run: Contains run scripts and configuration files for starting nodes and performing related operations.
9. Rust project files (Cargo.toml, rustfmt.toml, deny.toml): Rust project definitions and configuration files, managing dependencies, code formatting, and security checks, etc.

### Directory Structure

#### Key Crate Reference

| Crate | Description |
|-------|-------------|
| `cfxcore` | The core engine layer of the Conflux blockchain, containing consensus algorithms (PoW and PoS), block synchronization, transaction pool management, block data management, light node protocol, and other blockchain node core functional modules. |
| `execution` | EVM transaction executor |
| `dbs` | Contains the layered data storage system of the Conflux blockchain, from the underlying RocksDB key-value database wrapper to the upper-layer MPT state tree, snapshot management, and account state database complete storage architecture. |
| `network` | P2P network communication |
| `client` | client startup |
| `rpc` | RPC implementation (using jsonrpsee) |
| `pos/*` | PoS consensus, cryptography, storage |
| `cfx_types` | Blockchain common types (Address, U256, H256) |
| `primitives` | Core data structures (Block, Transaction, Receipt) |
| `config` | Node configuration management |

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

## Development Workflow

### Key Design Principles

- **Modularity**: Each crate can be used as a standalone library
- **Performance**: Extensive use of parallelism, memory-mapped I/O, and optimized data structures
- **Extensibility**: Traits and generic types allow for different chain implementations
- **Type Safety**: Strong typing throughout with minimal use of dynamic dispatch

### Testing Guidelines

1. **Unit Tests**: Test individual functions and components
2. **Integration Tests**: Test interactions between components
3. **Benchmarks**: For performance-critical code
4. **Fuzz Tests**: For parsing and serialization code
5. **Property Tests**: For checking component correctness on a wide variety of inputs

Example test structure:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_component_behavior() {
        // Arrange
        let component = Component::new();
        
        // Act
        let result = component.operation();
        
        // Assert
        assert_eq!(result, expected);
    }
}
```

### Performance Considerations

1. **Avoid Allocations in Hot Paths**: Use references and borrowing
2. **Parallel Processing**: Use rayon for CPU-bound parallel work
3. **Async/Await**: Use tokio for I/O-bound operations

### Common Pitfalls

1. **Don't Block Async Tasks**: Use `spawn_blocking` for CPU-intensive work or work with lots of blocking I/O
2. **Handle Errors Properly**: Use `?` operator and proper error types

### What to Avoid

Based on PR patterns, avoid:

1. **Large, sweeping changes**: Keep PRs focused and reviewable
2. **Mixing unrelated changes**: One logical change per PR
3. **Ignoring CI failures**: All checks must pass
4. **Incomplete implementations**: Finish features before submitting

### Opening PRs against `master` branch

#### Titles

Use [Conventional Commits](https://www.conventionalcommits.org/) with an optional scope:

```
<type>(<scope>): <short description>
```

**Types**: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`

**Scope** (optional): crate or area, e.g. `evm`, `trie`, `rpc`, `engine`, `net`

Examples:
- `fix(rpc): correct gas estimation for ERC-20 transfers`
- `perf: batch trie updates to reduce cursor overhead`
- `feat(engine): add new_payload_interval metric`

#### Descriptions

Keep it short. Say what changed and why — nothing more.

**Do:**
- Write 1–3 sentences summarizing the change
- Explain _why_ if the diff doesn't make it obvious
- Link related issues or EIPs
- Include benchmark numbers for perf changes

**Don't:**
- List every file changed — that's what the diff is for
- Repeat the title in the body
- Add "Files changed" or "Changes" sections
- Write walls of text that go stale when the diff is updated
- Use filler like "This PR introduces...", "comprehensive", "robust", "enhance", "leverage"

**Template:**

```
Closes #<issue>

<what changed, 1-3 sentences>

<why, if not obvious from the diff>
```

**Good example:**

```
Closes #16800

Adds fallback for external IP resolution so node startup doesn't fail
when STUN is unreachable. Falls back to the configured default.
```

**Bad example:**

```
## Summary
This PR introduces comprehensive improvements to the IP resolution system.

## Changes
- Modified `crates/net/discv4/src/lib.rs` to add fallback
- Modified `crates/net/discv4/src/config.rs` to add default IP
- Added tests in `crates/net/discv4/src/tests/ip.rs`

## Files Changed
- crates/net/discv4/src/lib.rs
- crates/net/discv4/src/config.rs
- crates/net/discv4/src/tests/ip.rs
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
pytest ./integration_tests/tests -vv -n 6 --dist loadscope   # integration_tests/ directory
python3 tests/test_all.py                                    # tests/ directory
```

### Running Node

```bash
# Start mainnet node
./target/release/conflux

./target/release/conflux --config ./run/hydra.toml

# Show help
./target/release/conflux --help
```

### Common Development Commands

```bash
# Check code compiles (no binary generation)
cargo check --all

cargo deny check
```
