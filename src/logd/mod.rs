//! Exact shared log records; only remote durable ACK permits local deletion.
#[cfg(target_os = "linux")]
pub mod forward;
