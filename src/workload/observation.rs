//! Authoritative workload observations and durable, signed delivery.
use super::{
    ACK_DOMAIN, OBSERVATION_DOMAIN, PROTOCOL_MAJOR,
    store::{Store, WorkloadState},
};
use crate::{Error, Result, identity::Identity};
use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedState {
    Pending,
    Preparing,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessHealth {
    Unknown,
    Alive,
    Exited,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub workload_id: String,
    pub placement_id: String,
    pub generation: u64,
    pub desired_hash: [u8; 32],
    pub control_revision: u64,
    pub sandbox_id: String,
    pub observed_at_unix_ms: i64,
    pub state: ObservedState,
    pub process_health: ProcessHealth,
    pub reason_code: String,
    pub observation_revision: u64,
}

impl Observation {
    pub fn record(
        store: &Store,
        workload_id: &str,
        observed_state: ObservedState,
        process_health: ProcessHealth,
        reason_code: &str,
        now_ms: i64,
    ) -> Result<Self> {
        if reason_code.len() > 128
            || !reason_code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(Error::WorkloadState);
        }
        let mut state = store.load()?;
        let item = state
            .workloads
            .get(workload_id)
            .ok_or(Error::WorkloadState)?;
        let observation = Self {
            workload_id: workload_id.to_owned(),
            placement_id: item.authority.placement_id.clone(),
            generation: item.authority.generation,
            desired_hash: item.authority.desired_hash,
            control_revision: item.control_revision,
            sandbox_id: item.resources.sandbox_id.clone().unwrap_or_default(),
            observed_at_unix_ms: now_ms,
            state: observed_state,
            process_health,
            reason_code: reason_code.to_owned(),
            observation_revision: state
                .observations_revision
                .checked_add(1)
                .ok_or(Error::WorkloadState)?,
        };
        state.observations_revision = observation.observation_revision;
        state
            .workloads
            .get_mut(workload_id)
            .ok_or(Error::WorkloadState)?
            .last_observation = Some(observation.clone());
        store.save(&state)?;
        Ok(observation)
    }

    fn wire(&self) -> super::wire::WorkloadObservation {
        use super::wire::{ObservedState as WireState, ProcessHealth as WireHealth};
        let state = match self.state {
            ObservedState::Pending => WireState::Pending,
            ObservedState::Preparing => WireState::Preparing,
            ObservedState::Starting => WireState::Starting,
            ObservedState::Running => WireState::Running,
            ObservedState::Stopping => WireState::Stopping,
            ObservedState::Stopped => WireState::Stopped,
            ObservedState::Failed => WireState::Failed,
        };
        let health = match self.process_health {
            ProcessHealth::Unknown => WireHealth::Unknown,
            ProcessHealth::Alive => WireHealth::Alive,
            ProcessHealth::Exited => WireHealth::Exited,
        };
        super::wire::WorkloadObservation {
            node_id: String::new(),
            organization_id: String::new(),
            credential_generation: 0,
            workload_id: self.workload_id.clone(),
            placement_id: self.placement_id.clone(),
            generation: self.generation,
            desired_state_hash: self.desired_hash.to_vec(),
            control_revision: self.control_revision,
            sandbox_id: self.sandbox_id.clone(),
            observed_at_unix_ms: self.observed_at_unix_ms,
            state: state as i32,
            process_health: health as i32,
            reason_code: self.reason_code.clone(),
            observation_revision: self.observation_revision,
        }
    }
}

pub fn frame(
    state: &WorkloadState,
    identity: &Identity,
    request_id: &str,
    now_ms: i64,
) -> Result<Option<super::wire::ObservationFrame>> {
    if request_id.is_empty() || request_id.len() > 64 {
        return Err(Error::Identity);
    }
    let observations: Vec<_> = state
        .workloads
        .values()
        .filter_map(|item| item.last_observation.as_ref())
        .filter(|item| item.observation_revision > state.acknowledged_observation_revision)
        .map(Observation::wire)
        .map(|mut observation| {
            observation.node_id = identity.node_id.clone();
            observation.organization_id = identity.organization_id.clone();
            observation.credential_generation = identity.credential_generation;
            observation
        })
        .collect();
    if observations.is_empty() {
        return Ok(None);
    }
    let mut frame = super::wire::ObservationFrame {
        protocol_major: PROTOCOL_MAJOR,
        request_id: request_id.to_owned(),
        node_id: identity.node_id.clone(),
        credential_generation: identity.credential_generation,
        sent_at_unix_ms: now_ms,
        observations,
        signature: Vec::new(),
    };
    frame.signature = identity.sign_bytes(OBSERVATION_DOMAIN, &frame.encode_to_vec())?;
    Ok(Some(frame))
}

pub fn accept_ack(
    ack: super::wire::ObservationAck,
    root: &VerifyingKey,
    identity: &Identity,
    expected_request_id: &str,
    state: &WorkloadState,
    highest_sent_revision: u64,
    now_ms: i64,
) -> Result<u64> {
    let mut unsigned = ack.clone();
    unsigned.signature.clear();
    let signature = Signature::from_slice(&ack.signature).map_err(|_| Error::Identity)?;
    root.verify_strict(
        &[ACK_DOMAIN, &unsigned.encode_to_vec()].concat(),
        &signature,
    )
    .map_err(|_| Error::Identity)?;
    if ack.protocol_major != PROTOCOL_MAJOR
        || ack.request_id != expected_request_id
        || ack.node_id != identity.node_id
        || ack.credential_generation != identity.credential_generation
        || ack.issued_at_unix_ms <= 0
        || ack.issued_at_unix_ms > now_ms.saturating_add(30_000)
        || ack.accepted_through_revision < state.acknowledged_observation_revision
        || ack.accepted_through_revision > highest_sent_revision
    {
        return Err(Error::Identity);
    }
    Ok(ack.accepted_through_revision)
}

pub fn acknowledge(store: &Store, revision: u64) -> Result<()> {
    let mut state = store.load()?;
    if revision < state.acknowledged_observation_revision || revision > state.observations_revision
    {
        return Err(Error::Identity);
    }
    state.acknowledged_observation_revision = revision;
    store.save(&state)
}
