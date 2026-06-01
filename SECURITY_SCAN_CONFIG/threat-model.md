# Conflux-Rust Threat Model

## Overview

Conflux-rust is the Rust implementation of the Conflux protocol, a Layer 1 blockchain network. As a protocol-critical component handling untrusted network input, cryptographic operations, and state transitions, it faces significant security risks.

## Attack Surface

### Primary Entry Points

1. **Network Layer (P2P & RPC)**
   - Peer-to-peer message parsing and validation
   - RPC endpoint request handling
   - Protocol message deserialization
   - Connection state management

2. **Transaction & Block Processing**
   - Transaction parsing and validation
   - Block header validation
   - Merkle proof verification
   - State transition logic

3. **Cryptographic Operations**
   - Signature verification (ECDSA)
   - Hash computations (Keccak-256)
   - Public key recovery
   - Nonce/account state management

4. **Storage & State**
   - Trie data structure operations
   - Database access patterns
   - Account balance calculations
   - Nonce overflow/underflow

5. **Smart Contract Execution**
   - EVM bytecode parsing
   - Gas calculation and limits
   - Memory/storage access
   - Cross-space interactions (PoW ↔ PoS)

6. **Consensus Mechanism**
   - Block weight calculation
   - Fork resolution
   - Epoch transitions
   - Finalization logic

## Threat Categories

### Critical (Memory Safety / Logic Flaws)

- **Panic Attacks**: Code panics on malformed input (DoS vector)
- **Integer Overflow/Underflow**: Balance calculations, nonce tracking, gas accounting
- **Unsafe Block Errors**: Logic errors in `unsafe {}` sections
- **Unwrap/Expect on Untrusted Data**: Panics on crafted network input

### High (Cryptographic)

- **Signature Verification Bypass**: Incorrect ECDSA validation
- **Hash Collision Handling**: State inconsistency from hash mismatches
- **Private Key Exposure**: Unintended key leakage
- **Replay Attack Gaps**: Missing transaction uniqueness checks

### High (Consensus & State)

- **Double Spending**: State transition logic allowing same token use twice
- **Invalid State Transitions**: Accepting invalid block/transaction sequences
- **Weight Calculation Errors**: Incorrect consensus weight favoring attacker
- **Finality Violations**: Reorg attacks by re-finalizing blocks

### Medium (Availability)

- **Unbounded Resource Consumption**: No limits on processing time/memory
- **Algorithmic Complexity Attacks**: O(n²) operations on large inputs
- **Storage Exhaustion**: Unpriced storage writes

## Key Modules to Review

```
crates/
├── cfx_bytes/              # Byte serialization/deserialization
├── cfx_types/              # Core type definitions
├── cfx_utils/              # Utility functions
├── cfxcore/
│   ├── transaction/        # Transaction validation & execution
│   ├── block_gen/          # Block construction & validation
│   ├── consensus/          # Consensus algorithm
│   ├── state/              # State management & storage
│   └── vm/                 # Smart contract execution
├── network/                # P2P protocol & message handling
├── rpc/                    # RPC endpoint handling
├── primitives/             # Hash, signature, address types
└── storage/                # Database and trie operations
```

## Known Attack Vectors (for reference)

- Craft transaction with invalid signature but valid format
- Send block with weight calculation that exploits integer truncation
- Trigger state transitions with edge-case account balances (0, MAX_INT)
- Parse network messages with nested/deeply layered encoding
- Exploit panic conditions in error paths

## Verification Strategy

Focus on:
1. **Parser robustness**: Malformed bytes → no crash, graceful error handling
2. **Boundary conditions**: Min/max values, overflows, underflows
3. **Cryptographic correctness**: Signature validation, nonce uniqueness
4. **Consensus logic**: Weight calculations, fork resolution
5. **Panic-freedom**: All unwrap/expect on untrusted data must be eliminated or guarded
