//! Suwappu EVM dev node — CLI entry point.
//!
//! See [`suwappu_node`] for the library modules that back this binary.
//!
//! **NOT production.** No p2p, no consensus, no persistence across restarts.
//! One transaction = one block (instant-mine).

#![warn(missing_docs)]
#![allow(unreachable_pub)]

use clap::Parser;
use suwappu_node::{node::SuwappuNode, rpc};

/// Command-line arguments for the Suwappu dev node.
#[derive(Debug, Parser)]
#[command(name = "suwappu-node")]
#[command(about = "Suwappu EVM dev node (instant-mine, MonadPrecompiles 0x0101+0x0102)")]
pub struct Args {
    /// TCP port to listen on.
    #[arg(long, default_value_t = 8545)]
    pub port: u16,

    /// EVM chain ID returned by eth_chainId / net_version.
    #[arg(long, default_value_t = 31337)]
    pub chain_id: u64,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let node = SuwappuNode::new(args.chain_id);
    rpc::serve(node, args.port).await;
}
