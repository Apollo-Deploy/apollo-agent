//! Linux telemetry agent. Existing signed Node V2 remains lifecycle authority.
#![forbid(unsafe_code)]
pub mod cgroup;
pub mod config;
pub mod control;
pub mod daemon;
pub mod error;
pub mod identity;
pub mod logd;
pub mod network;
pub mod session;
pub mod store;
pub mod telemetry;
pub use error::{Error, Result};

pub fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}
