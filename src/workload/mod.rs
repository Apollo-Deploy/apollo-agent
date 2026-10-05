//! Signed node workload authority, durable local state and reconciliation.
pub mod artifactd;
pub mod authority;
pub mod control;
mod driver;
pub mod observation;
pub mod reconcile;
pub mod sandboxd;
pub mod store;
pub use driver::run_once;
pub mod wire {
    pub use apollo_node_telemetry_protocol::workload_wire::*;
}

pub const AUTHORITY_DOMAIN: &[u8] = b"apollo.workload.authority.v1\0";
pub const REQUEST_DOMAIN: &[u8] = b"apollo.workload.authority-request.v1\0";
pub const OBSERVATION_DOMAIN: &[u8] = b"apollo.workload.observation.v1\0";
pub const ACK_DOMAIN: &[u8] = b"apollo.workload.observation-ack.v1\0";
pub const PROTOCOL_MAJOR: u32 = 1;
pub const MAX_AUTHORITY_BYTES: usize = 1_048_576;
pub const MAX_WORKLOADS: usize = 1;
pub const MAX_STATE_BYTES: usize = 16 * 1_048_576;
pub const MAX_GENERATIONS: usize = 64;
