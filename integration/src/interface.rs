//! Interface module for I Protocol V5
//!
//! This module provides the main protocol interface and types
//! that external applications and examples should use.

// Re-export the main protocol implementation
pub use crate::{
    IProtocolV5,
    ProtocolConfig,
    ProtocolState,
    ProtocolError,
    Transaction,
    Block,
    SlotResult,
    VdfBackendType,
    Hash256,
};