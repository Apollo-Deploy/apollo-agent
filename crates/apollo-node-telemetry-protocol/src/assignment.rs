use crate::{
    ASSIGNMENT_DOMAIN, MAX_WORKLOADS, PROTOCOL_MAJOR, ProtocolError,
    authentication::verify,
    wire::{AssignmentSnapshot, WorkloadAssignment},
};
use apollo_domain::ids::{NodeId, PlacementId, WorkloadId};
use ed25519_dalek::VerifyingKey;
use prost::Message;
use std::collections::{HashMap, HashSet};

/// Only this validated type may authorize node telemetry. The server loads it
/// from its control-plane feed, never from a node-provided frame.
#[derive(Clone)]
pub struct Assignments {
    snapshot: AssignmentSnapshot,
}

impl Assignments {
    pub fn authenticate(
        snapshot: AssignmentSnapshot,
        root: &VerifyingKey,
        now_ms: i64,
    ) -> Result<Self, ProtocolError> {
        let mut unsigned = snapshot.clone();
        unsigned.signature.clear();
        verify(
            ASSIGNMENT_DOMAIN,
            &unsigned.encode_to_vec(),
            &snapshot.signature,
            root,
        )?;
        NodeId::parse(snapshot.node_id.clone()).map_err(|_| ProtocolError)?;
        if snapshot.protocol_major != PROTOCOL_MAJOR
            || snapshot.revision == 0
            || snapshot.credential_generation == 0
            || snapshot.node_public_key.len() != 32
            || snapshot.issued_at_unix_ms > now_ms.saturating_add(30_000)
            || snapshot.issued_at_unix_ms <= 0
            || snapshot.expires_at_unix_ms <= now_ms
            || snapshot.expires_at_unix_ms <= snapshot.issued_at_unix_ms
            || snapshot
                .expires_at_unix_ms
                .saturating_sub(snapshot.issued_at_unix_ms)
                > 86_400_000
            || snapshot.workloads.len() > MAX_WORKLOADS
        {
            return Err(ProtocolError);
        }
        let mut workloads = HashSet::new();
        let mut streams = HashSet::new();
        let mut local_ids = HashSet::new();
        for workload in &snapshot.workloads {
            WorkloadId::parse(workload.workload_id.clone()).map_err(|_| ProtocolError)?;
            PlacementId::parse(workload.placement_id.clone()).map_err(|_| ProtocolError)?;
            if workload.generation == 0
                || workload.desired_workload_sha256.len() != 32
                || workload.local_workload_id.len() != 16
                || workload.local_workload_id.iter().all(|b| *b == 0)
                || !local_ids.insert(&workload.local_workload_id)
                || !workloads.insert(&workload.workload_id)
                || workload.log_stream_ids.is_empty()
                || workload.log_stream_ids.len() > 8
            {
                return Err(ProtocolError);
            }
            for stream in &workload.log_stream_ids {
                if stream.len() != 16 || stream.iter().all(|b| *b == 0) || !streams.insert(stream) {
                    return Err(ProtocolError);
                }
            }
        }
        Ok(Self { snapshot })
    }

    pub fn snapshot(&self) -> &AssignmentSnapshot {
        &self.snapshot
    }

    pub fn replace(&mut self, newer: Self) -> Result<(), ProtocolError> {
        let old = &self.snapshot;
        let next = &newer.snapshot;
        if next.node_id != old.node_id
            || next.credential_generation < old.credential_generation
            || (next.credential_generation == old.credential_generation
                && next.node_public_key != old.node_public_key)
            || next.revision < old.revision
            || next.issued_at_unix_ms < old.issued_at_unix_ms
            || (next.revision == old.revision && next.workloads != old.workloads)
        {
            return Err(ProtocolError);
        }
        fence_workloads(&old.workloads, &next.workloads)?;
        *self = newer;
        Ok(())
    }
}

/// Compare current authority with immutable historical bindings as well as the
/// immediately preceding snapshot. Storage owners retain these tombstones.
pub fn fence_workloads(
    history: &[WorkloadAssignment],
    next: &[WorkloadAssignment],
) -> Result<(), ProtocolError> {
    let mut latest: HashMap<&str, &WorkloadAssignment> = HashMap::new();
    let mut streams = HashMap::new();
    for binding in history {
        latest
            .entry(&binding.workload_id)
            .and_modify(|previous| {
                if binding.generation > previous.generation {
                    *previous = binding;
                }
            })
            .or_insert(binding);
        for stream in &binding.log_stream_ids {
            streams.insert(stream, binding);
        }
    }
    for assignment in next {
        if let Some(previous) = latest.get(assignment.workload_id.as_str())
            && (assignment.generation < previous.generation
                || (assignment.generation == previous.generation
                    && (assignment.desired_workload_sha256 != previous.desired_workload_sha256
                        || assignment.placement_id != previous.placement_id
                        || assignment.local_workload_id != previous.local_workload_id
                        || assignment.log_stream_ids != previous.log_stream_ids)))
        {
            return Err(ProtocolError);
        }
        for stream in &assignment.log_stream_ids {
            if let Some(previous) = streams.get(stream)
                && (assignment.workload_id != previous.workload_id
                    || assignment.placement_id != previous.placement_id
                    || assignment.generation != previous.generation
                    || assignment.local_workload_id != previous.local_workload_id
                    || assignment.desired_workload_sha256 != previous.desired_workload_sha256)
            {
                return Err(ProtocolError);
            }
        }
    }
    Ok(())
}
