//! Cloud/BYOC ingest authority checks, independent of node-supplied ownership.
use crate::{
    ACK_DOMAIN, CLIENT_DOMAIN, MAX_EVENTS, PROTOCOL_MAJOR, ProtocolError,
    assignment::Assignments,
    authentication::verify,
    decode_canonical,
    wire::{self, client_frame},
};
use ed25519_dalek::VerifyingKey;
use prost::Message;

pub fn authenticate_client(
    bytes: &[u8],
    assignments: &Assignments,
    now_ms: i64,
) -> Result<wire::ClientFrame, ProtocolError> {
    let frame: wire::ClientFrame = decode_canonical(bytes)?;
    let scope = assignments.snapshot();
    if frame.protocol_major != PROTOCOL_MAJOR
        || frame.node_id != scope.node_id
        || frame.credential_generation != scope.credential_generation
        || frame.assignment_revision != scope.revision
        || scope.expires_at_unix_ms <= now_ms
        || frame.boot_id.len() != 16
        || frame.message_id.len() != 16
        || frame.boot_id.iter().all(|b| *b == 0)
        || frame.message_id.iter().all(|b| *b == 0)
        || frame.sent_at_unix_ms.abs_diff(now_ms) > 300_000
    {
        return Err(ProtocolError);
    }
    let key: [u8; 32] = scope
        .node_public_key
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolError)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| ProtocolError)?;
    let mut unsigned = frame.clone();
    unsigned.signature.clear();
    verify(
        CLIENT_DOMAIN,
        &unsigned.encode_to_vec(),
        &frame.signature,
        &key,
    )?;
    match frame.body.as_ref().ok_or(ProtocolError)? {
        client_frame::Body::Heartbeat(h) => {
            if h.agent_version.len() > 128 || h.active_mappings as usize > scope.workloads.len() {
                return Err(ProtocolError);
            }
        }
        client_frame::Body::Metrics(batch) => {
            if batch.sequence == 0 || batch.samples.is_empty() || batch.samples.len() > 128 {
                return Err(ProtocolError);
            }
            let mut slots = std::collections::HashSet::new();
            for sample in &batch.samples {
                if sample.assignment_slot as usize >= scope.workloads.len()
                    || !slots.insert(sample.assignment_slot)
                    || sample.timestamp_unix_ms <= 0
                    || sample.timestamp_unix_ms > now_ms.saturating_add(30_000)
                    || sample
                        .cpu
                        .as_ref()
                        .and_then(|c| c.core_equivalents)
                        .is_some_and(|v| !v.is_finite() || v < 0.0)
                {
                    return Err(ProtocolError);
                }
                for psi in [
                    &sample.cpu_pressure,
                    &sample.memory_pressure,
                    &sample.io_pressure,
                ]
                .into_iter()
                .flatten()
                {
                    for value in [&psi.some, &psi.full].into_iter().flatten() {
                        if [value.avg10, value.avg60, value.avg300]
                            .iter()
                            .any(|v| !v.is_finite() || !(0.0..=100.0).contains(v))
                        {
                            return Err(ProtocolError);
                        }
                    }
                }
            }
        }
        client_frame::Body::Events(batch) => {
            if batch.events.is_empty() || batch.events.len() > MAX_EVENTS {
                return Err(ProtocolError);
            }
            for event in &batch.events {
                if event.assignment_slot as usize >= scope.workloads.len()
                    || event.event_id.len() != 16
                    || event.event_id.iter().all(|b| *b == 0)
                    || event.timestamp_unix_ms <= 0
                    || event.timestamp_unix_ms > now_ms.saturating_add(30_000)
                    || wire::EventKind::try_from(event.kind)
                        .ok()
                        .is_none_or(|k| k == wire::EventKind::Unspecified)
                {
                    return Err(ProtocolError);
                }
            }
        }
        client_frame::Body::Logs(logs) => {
            validate_log(logs, assignments)?;
        }
    }
    Ok(frame)
}

pub fn validate_log(
    logs: &wire::LogBatch,
    assignments: &Assignments,
) -> Result<u64, ProtocolError> {
    if logs.stream_id.len() != 16
        || logs.encoded_records.is_empty()
        || logs.encoded_records.len() > apollo_telemetry_protocol::MAX_PACKET - 16
        || logs.first_sequence == 0
        || logs.last_sequence < logs.first_sequence
        || logs.encoded_len() > crate::MAX_FRAME_BYTES - 512
        || !assignments
            .snapshot()
            .workloads
            .iter()
            .any(|a| a.generation == logs.generation && a.log_stream_ids.contains(&logs.stream_id))
    {
        return Err(ProtocolError);
    }
    let mut remaining = logs.encoded_records.as_slice();
    let mut previous = None;
    while !remaining.is_empty() {
        let length =
            apollo_telemetry_protocol::record::length(remaining).map_err(|_| ProtocolError)?;
        let record = remaining.get(..length).ok_or(ProtocolError)?;
        let (header, payload) =
            apollo_telemetry_protocol::record::decode(record).map_err(|_| ProtocolError)?;
        if header.stream.0.as_slice() != logs.stream_id || header.generation != logs.generation {
            return Err(ProtocolError);
        }
        let first = if header.kind == apollo_telemetry_protocol::record::RecordKind::Gap {
            apollo_telemetry_protocol::Gap::decode(payload)
                .map_err(|_| ProtocolError)?
                .first
        } else {
            header.sequence
        };
        let expected = previous
            .and_then(|v: u64| v.checked_add(1))
            .unwrap_or(logs.first_sequence);
        if first != expected {
            return Err(ProtocolError);
        }
        previous = Some(header.sequence);
        remaining = &remaining[length..];
    }
    if previous != Some(logs.last_sequence) {
        return Err(ProtocolError);
    }
    Ok(logs.last_sequence)
}

pub fn ack_for(frame: &wire::ClientFrame, now_ms: i64) -> Result<wire::DurableAck, ProtocolError> {
    let (kind, stream_id, generation, cumulative_sequence) =
        match frame.body.as_ref().ok_or(ProtocolError)? {
            client_frame::Body::Heartbeat(_) => (wire::AckKind::Heartbeat, vec![], 0, 0),
            client_frame::Body::Metrics(_) => (wire::AckKind::Metrics, vec![], 0, 0),
            client_frame::Body::Events(_) => (wire::AckKind::Events, vec![], 0, 0),
            client_frame::Body::Logs(logs) => (
                wire::AckKind::Logs,
                logs.stream_id.clone(),
                logs.generation,
                logs.last_sequence,
            ),
        };
    Ok(wire::DurableAck {
        protocol_major: PROTOCOL_MAJOR,
        node_id: frame.node_id.clone(),
        credential_generation: frame.credential_generation,
        assignment_revision: frame.assignment_revision,
        boot_id: frame.boot_id.clone(),
        message_id: frame.message_id.clone(),
        kind: kind as i32,
        stream_id,
        generation,
        cumulative_sequence,
        issued_at_unix_ms: now_ms,
        durable: false,
        signature: vec![],
    })
}

pub fn authenticate_ack(
    bytes: &[u8],
    frame: &wire::ClientFrame,
    root: &VerifyingKey,
    now_ms: i64,
) -> Result<wire::DurableAck, ProtocolError> {
    let ack: wire::DurableAck = decode_canonical(bytes)?;
    let mut unsigned = ack.clone();
    unsigned.signature.clear();
    verify(ACK_DOMAIN, &unsigned.encode_to_vec(), &ack.signature, root)?;
    let mut expected = ack_for(frame, ack.issued_at_unix_ms)?;
    expected.durable = ack.durable;
    expected.signature.clone_from(&ack.signature);
    if ack != expected
        || ack.issued_at_unix_ms.abs_diff(now_ms) > 30_000
        || ((ack.kind == wire::AckKind::Logs as i32 || ack.kind == wire::AckKind::Events as i32)
            && !ack.durable)
    {
        return Err(ProtocolError);
    }
    Ok(ack)
}
