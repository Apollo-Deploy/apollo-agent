//! Remote telemetry authority and bounded protobuf contracts.
//! Local log records are defined by apollo-telemetry-protocol.
#![forbid(unsafe_code)]
pub mod assignment;
pub mod authentication;
pub mod request;
pub mod validation;
pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/apollo.telemetry.v1.rs"));
}
pub mod workload_wire {
    include!(concat!(env!("OUT_DIR"), "/apollo.workload.v1.rs"));
}
pub const PROTOCOL_MAJOR: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 262_144;
pub const MAX_WORKLOADS: usize = 1_024;
pub const MAX_EVENTS: usize = 256;
pub const ASSIGNMENT_DOMAIN: &[u8] = b"apollo.telemetry.assignment.v1\0";
pub const CLIENT_DOMAIN: &[u8] = b"apollo.telemetry.client.v1\0";
pub const ACK_DOMAIN: &[u8] = b"apollo.telemetry.ack.v1\0";

#[derive(Debug, thiserror::Error)]
#[error("telemetry protocol rejected")]
pub struct ProtocolError;

pub fn decode_canonical<M: prost::Message + Default>(bytes: &[u8]) -> Result<M, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError);
    }
    let value = M::decode(bytes).map_err(|_| ProtocolError)?;
    if value.encode_to_vec() != bytes {
        return Err(ProtocolError);
    }
    Ok(value)
}
