//! Braidpool Common Utilities
//!
//! This crate provides shared functionality used across all Braidpool workspace crates,
//! including cpunet-specific block hash computation and address encoding.

pub mod cpunet;

// Re-export commonly used items at crate root
pub use cpunet::{compute_block_hash, Cpunet, CpunetAddressError, CpunetParams, ParseCpunetError};
