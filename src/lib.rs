//! Linux node agent for signed workload reconciliation and telemetry relay.
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
pub mod workload;
pub use error::{Error, Result};

pub fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}
