# Conflux Binary Features

This document describes the available compile-time features for `bins/conflux`, defined in `bins/conflux/Cargo.toml`.

## Default Features

### `jemalloc-global` (default)

Uses jemalloc as the global memory allocator with malloc_size_of statistics enabled.

## Optional Features

### Storage Related

| Feature | Description |
|---------|-------------|
| `u64-mpt-db-key` | Use u64 as MPT database key |

### EVM Related

| Feature | Description |
|---------|-------------|
| `align_evm` | Align EVM execution for same behavior with Ethereum vanilla EVM |

### Memory Allocator Related

| Feature | Description |
|---------|-------------|
| `jemalloc-global` | Use jemalloc as the global memory allocator (default) |
| `jemalloc-prof` | Enable jemalloc profiling support |
| `tracy-allocator` | Use Tracy memory allocator |
| `snmalloc` | Use snmalloc memory allocator |
| `snmalloc-native` | Use snmalloc-native memory allocator |

> **Note**: Since jemalloc is the default and takes precedence over snmalloc when both are enabled, use `--no-default-features` when enabling snmalloc or snmalloc-native to disable jemalloc.

### Debugging Related

| Feature | Description |
|---------|-------------|
| `deadlock-detection` | Enable parking_lot deadlock detection |

### BLS Signature Related

| Feature | Description |
|---------|-------------|
| `blst-portable` | Use BLST signature library in portable mode (suitable for environments without hardware acceleration) |

## Usage Examples

### Disable Default Features

```bash
cargo build --no-default-features --features snmalloc
```

### Enable Debug Features

```bash
cargo build --features deadlock-detection
```

### Production Build

```bash
cargo build --release
```

## Feature Dependency Graph

```
jemalloc-global
├── malloc_size_of/jemalloc
└── cfx-mallocator-utils/jemalloc

jemalloc-prof
├── cfx-mallocator-utils/jemalloc
└── cfx-mallocator-utils/jemalloc-prof

blst-portable
└── bls-signatures/blst-portable

align_evm
├── cfx-executor/align_evm
└── cfx-execute-helper/align_evm
```
