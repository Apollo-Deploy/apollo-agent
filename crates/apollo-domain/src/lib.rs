//! Bounded identifier subset needed by the standalone telemetry agent.
#![forbid(unsafe_code)]
mod error;
pub mod ids;
pub use error::DomainError;
