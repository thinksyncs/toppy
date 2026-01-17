//! Protocol definitions for communication between Toppy clients and gateways.
//!
//! This crate will define the custom capsule types and control messages
//! used by the MASQUE implementation. For now, it contains only placeholders.

/// An empty struct representing a placeholder protocol message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderMessage;

impl PlaceholderMessage {
    /// Creates a new placeholder message.
    pub fn new() -> Self {
        Self
    }
}