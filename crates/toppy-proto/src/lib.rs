//! Protocol definitions for communication between Toppy clients and gateways.
//!
//! This crate defines minimal capsule and control message types used by the CLI
//! and gateway during early development.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    pub kind: u16,
    pub payload: Vec<u8>,
}

impl Capsule {
    pub fn new(kind: u16, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            payload: payload.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    Ping,
    Pong,
    Close { reason: String },
}

impl ControlMessage {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Close { .. })
    }
}
