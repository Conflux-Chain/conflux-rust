//! Conflux Executor: A Rust crate for the core logic of executing transactions
//! on the Conflux blockchain. It encapsulates all the necessary logic for a
//! consensus node during execution, focusing solely on the execution logic
//! without enhanced features like tracing or trace processing.

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate cfx_util_macros;
use substrate_bn as bn;

/// Ethereum Builtins: Implements Ethereum's builtin contracts, ranging from
/// address `0x1` to `0x9`.
mod builtin;

/// Execution Context: Implements the context during the execution, like
/// caller's information and block information. It also ensures compatibility
/// with the context interface of the EVM interpreter.
pub mod context;

/// Transaction Execution Entry: Manages the execution of transactions.
/// It is responsible for receiving transactions, performing checks according to
/// the Conflux specification, and submitting them to the execution engine.
pub mod executive;

/// Conflux Internal Contracts: Implements Conflux's builtin contracts.  
pub mod internal_contract;

/// Execution Engine Object: Serves as a factory for specifications, builtin
/// contracts (including internal contracts), and the EVM interpreter.
pub mod machine;

/// Tool Macros
mod macros;

/// Observability Interface: Defines a trait for extending functionality.
/// Extensions can implement this trait to observe detailed aspects of the
/// execution process.
pub mod observer;

/// Stack Management for Execution Engine: Conflux's execution engine is
/// stack-based. This module manages the stack operations, mainly handling the
/// logic related to pushing and popping frames.
pub mod stack;

/// Transaction Execution Tracker: Tracks and records consensus-matters details
/// during transaction execution.
pub mod substate;

/// Specification Control: Enables fine-grained control over the engine's
/// behavior during the execution of different blocks, allowing the engine to
/// achieve backward compatibility with different versions of the Conflux
/// specification per hardfork.
pub mod spec;

/// Ledger State: Acts as a caching and checkpoint layer built upon semantically
/// meaningful database interfaces for the execution.
pub mod state;

pub use internal_contract::{InternalContractMap, InternalContractTrait};
pub use observer as executive_observer;
