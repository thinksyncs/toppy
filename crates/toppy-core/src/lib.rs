//! Core functionality shared across all Toppy components.
//!
//! This crate will eventually contain configuration management, policy
//! evaluation, logging primitives, error types, and other utilities.

/// Returns a generic greeting. This is a placeholder to demonstrate a
/// compilable library function.
pub fn greeting() -> &'static str {
    "Hello from toppy-core!"
}

pub mod auth;
pub mod audit;
pub mod config;
pub mod doctor;
pub mod policy;
pub mod rate;
pub mod test_support;
