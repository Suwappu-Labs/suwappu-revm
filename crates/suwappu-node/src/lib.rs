//! Suwappu EVM dev node — library entry point (used by integration tests).
//!
//! The binary crate (`main.rs`) is the user-facing CLI. The library target
//! exposes the same modules so that integration tests can import
//! [`node::SuwappuNode`] and [`rpc::serve`] directly.
//!
//! **NOT production.** This is a dev-only node.

#![warn(missing_docs)]
#![allow(unreachable_pub)]

/// In-process EVM state machine: account balances, nonce tracking, tx
/// execution, and receipt storage.
pub mod node;

/// JSON-RPC HTTP server (axum-based) that wraps the node state.
pub mod rpc;
