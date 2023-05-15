#![allow(unused)]
pub mod config;
pub mod proof_type;
pub mod state;
pub mod state_index;
pub mod state_manager;
pub mod state_trait;
pub(crate) mod state_trees;

pub const CACHE_DEPTH: usize = 6;
