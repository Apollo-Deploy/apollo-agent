//! Enrollment-key proof for the bounded, read-only assignment channel.
use crate::{PROTOCOL_MAJOR, ProtocolError, authentication::verify, wire::AssignmentRequest};
use apollo_domain::ids::NodeId;
use ed25519_dalek::VerifyingKey;
use prost::Message;

pub const REQUEST_DOMAIN: &[u8] = b"apollo.telemetry.assignment-request.v1\0";

pub fn subject(node: &str, generation: u64) -> String {
    format!("apollo.node.telemetry.assignment.{node}.{generation}")
}

/// Control-plane publication only. Node enrollment grants no permission to
/// publish here; consumers additionally verify the durable authority signature.
pub fn authority_subject(node: &str, generation: u64) -> String {
    format!("apollo.telemetry.authority.{node}.{generation}")
}

pub fn authenticate(
    request: &AssignmentRequest,
    key: &VerifyingKey,
    now_ms: i64,
) -> Result<(), ProtocolError> {
    NodeId::parse(request.node_id.clone()).map_err(|_| ProtocolError)?;
    if request.protocol_major != PROTOCOL_MAJOR
        || request.credential_generation == 0
        || request.request_id.len() != 16
        || request.request_id.iter().all(|b| *b == 0)
        || request.sent_at_unix_ms <= 0
        || request.sent_at_unix_ms.abs_diff(now_ms) > 30_000
    {
        return Err(ProtocolError);
    }
    let mut unsigned = request.clone();
    unsigned.signature.clear();
    verify(
        REQUEST_DOMAIN,
        &unsigned.encode_to_vec(),
        &request.signature,
        key,
    )
}
