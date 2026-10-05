//! Crash-durable workload authority, daemon identities and one pending operation.
use super::{
    MAX_GENERATIONS, MAX_STATE_BYTES,
    authority::{AcceptedSnapshot, WorkloadAuthority},
};
use crate::{
    Error, Result,
    store::{durable_write, private_read},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

const STATE_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonResources {
    pub artifact_digest: Option<String>,
    pub artifact_pin_id: Option<String>,
    pub prepared_artifact_id: Option<String>,
    pub manifest_digest: Option<String>,
    pub artifact_lease_id: Option<String>,
    pub sandbox_image_digest: Option<String>,
    pub sandbox_id: Option<String>,
    pub sandbox_present: bool,
    pub sandbox_generation: Option<u64>,
    pub session_generation: Option<u64>,
    pub sandbox_lease_id: Option<String>,
    pub sandbox_lease_expires_at_unix_ms: i64,
    pub lease_renewal_sequence: u64,
    pub exec_id: Option<String>,
    pub exec_attempt: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetiringGeneration {
    pub authority: WorkloadAuthority,
    pub resources: DaemonResources,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingOperation {
    pub daemon: String,
    pub action: String,
    pub workload_id: String,
    pub generation: u64,
    pub operation_id: String,
    pub operation_sequence: u64,
    /// Exact CBOR/JSON semantic request; retries must serialize these same fields.
    pub request: Value,
    pub started_at_unix_ms: i64,
}

pub struct OperationIntent {
    pub daemon: &'static str,
    pub action: String,
    pub workload_id: String,
    pub generation: u64,
    pub operation_id: String,
    pub operation_sequence: u64,
    pub request: Value,
    pub started_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredWorkload {
    pub authority: WorkloadAuthority,
    pub control_revision: u64,
    pub authority_expiry_unix_ms: i64,
    pub resources: DaemonResources,
    pub retiring: Vec<RetiringGeneration>,
    pub last_observation: Option<super::observation::Observation>,
    pub retry_after_unix_ms: i64,
    pub failures: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadState {
    pub control_revision: u64,
    pub request_id: String,
    pub signed_snapshot_hash: String,
    pub next_operation_sequence: u64,
    pub generations_seen: BTreeMap<String, u64>,
    pub workloads: BTreeMap<String, StoredWorkload>,
    pub pending: Option<PendingOperation>,
    pub observations_revision: u64,
    pub acknowledged_observation_revision: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    checksum: String,
    payload: String,
}

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn open(directory: &Path) -> Result<Self> {
        let path = directory.join("workload-state.json");
        let store = Self { path };
        if store.path.exists() {
            let _ = store.load()?;
        }
        Ok(store)
    }

    pub fn load(&self) -> Result<WorkloadState> {
        if !self.path.exists() {
            return Ok(WorkloadState::default());
        }
        let bytes = private_read(&self.path, MAX_STATE_BYTES)?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| Error::WorkloadState)?;
        if envelope.version != STATE_VERSION {
            return Err(Error::WorkloadState);
        }
        let digest = hex(&Sha256::digest(envelope.payload.as_bytes()));
        if digest != envelope.checksum || envelope.payload.len() > MAX_STATE_BYTES {
            return Err(Error::WorkloadState);
        }
        let state: WorkloadState =
            serde_json::from_str(&envelope.payload).map_err(|_| Error::WorkloadState)?;
        if state.workloads.len() > 1
            || state.generations_seen.len() > MAX_GENERATIONS
            || state.next_operation_sequence > i64::MAX as u64
            || state
                .workloads
                .iter()
                .any(|(id, item)| id != &item.authority.workload_id)
        {
            return Err(Error::WorkloadState);
        }
        Ok(state)
    }

    pub fn save(&self, state: &WorkloadState) -> Result<()> {
        if state.workloads.len() > 1
            || state.generations_seen.len() > MAX_GENERATIONS
            || state.next_operation_sequence > i64::MAX as u64
        {
            return Err(Error::WorkloadState);
        }
        let payload = serde_json::to_string(state).map_err(|_| Error::WorkloadState)?;
        if payload.len() > MAX_STATE_BYTES - 256 {
            return Err(Error::WorkloadState);
        }
        let envelope = Envelope {
            version: STATE_VERSION,
            checksum: hex(&Sha256::digest(payload.as_bytes())),
            payload,
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|_| Error::WorkloadState)?;
        durable_write(&self.path, &bytes)
    }

    pub fn update(&self, update: impl FnOnce(&mut WorkloadState) -> Result<()>) -> Result<()> {
        let mut state = self.load()?;
        update(&mut state)?;
        self.save(&state)
    }

    /// Accept the signed snapshot only after the caller verifies its signature.
    /// Equal revisions are idempotent only for the exact same authenticated head.
    pub fn accept(&self, snapshot: AcceptedSnapshot, signed_bytes: &[u8]) -> Result<WorkloadState> {
        let mut state = self.load()?;
        let fingerprint = hex(&Sha256::digest(signed_bytes));
        if snapshot.control_revision < state.control_revision {
            return Err(Error::StaleAuthority);
        }
        if snapshot.control_revision == state.control_revision {
            if state.signed_snapshot_hash == fingerprint && state.request_id == snapshot.request_id
            {
                return Ok(state);
            }
            // Every live reply is bound to a fresh request ID. Permit a signed
            // lease refresh at the same control revision only when the complete
            // desired workload set and every generation/hash are unchanged.
            if snapshot.workloads.len() != state.workloads.len()
                || snapshot.workloads.iter().any(|authority| {
                    state
                        .workloads
                        .get(&authority.workload_id)
                        .is_none_or(|item| {
                            item.authority.generation != authority.generation
                                || item.authority.desired_hash != authority.desired_hash
                        })
                })
            {
                return Err(Error::StaleAuthority);
            }
            for authority in snapshot.workloads {
                let item = state
                    .workloads
                    .get_mut(&authority.workload_id)
                    .ok_or(Error::StaleAuthority)?;
                item.authority = authority;
                item.authority_expiry_unix_ms = snapshot.expires_at_unix_ms;
            }
            state.request_id = snapshot.request_id;
            state.signed_snapshot_hash = fingerprint;
            self.save(&state)?;
            return Ok(state);
        }
        let new_ids = snapshot
            .workloads
            .iter()
            .filter(|w| !state.generations_seen.contains_key(&w.workload_id))
            .count();
        if state.generations_seen.len() + new_ids > MAX_GENERATIONS {
            return Err(Error::WorkloadState);
        }
        for authority in &snapshot.workloads {
            if let Some(previous) = state.generations_seen.get(&authority.workload_id) {
                if authority.generation < *previous {
                    return Err(Error::StaleAuthority);
                }
                if authority.generation == *previous {
                    let existing = state
                        .workloads
                        .get(&authority.workload_id)
                        .ok_or(Error::StaleAuthority)?;
                    if authority.desired_hash != existing.authority.desired_hash {
                        return Err(Error::StaleAuthority);
                    }
                }
            }
        }
        let expiry = snapshot.expires_at_unix_ms;
        let mut next = BTreeMap::new();
        for authority in snapshot.workloads {
            let id = authority.workload_id.clone();
            let previous = state.workloads.remove(&id);
            let mut retiring = previous
                .as_ref()
                .map(|w| w.retiring.clone())
                .unwrap_or_default();
            if let Some(old) = previous
                .as_ref()
                .filter(|w| w.authority.generation != authority.generation)
            {
                let operation_in_flight = state.pending.as_ref().is_some_and(|pending| {
                    pending.workload_id == id && pending.generation == old.authority.generation
                });
                if has_resources(&old.resources) || operation_in_flight {
                    retiring.push(RetiringGeneration {
                        authority: old.authority.clone(),
                        resources: old.resources.clone(),
                    });
                }
            }
            if retiring.len() > MAX_GENERATIONS {
                return Err(Error::WorkloadState);
            }
            let same_generation = previous
                .as_ref()
                .filter(|w| w.authority.generation == authority.generation);
            let resources = same_generation
                .map(|w| w.resources.clone())
                .unwrap_or_default();
            let last_observation = previous
                .as_ref()
                .filter(|w| w.authority.generation == authority.generation)
                .and_then(|w| w.last_observation.clone());
            state
                .generations_seen
                .insert(id.clone(), authority.generation);
            next.insert(
                id,
                StoredWorkload {
                    authority,
                    control_revision: snapshot.control_revision,
                    authority_expiry_unix_ms: expiry,
                    resources,
                    last_observation,
                    retiring,
                    retry_after_unix_ms: 0,
                    failures: 0,
                },
            );
        }
        // A missing prior workload stays in durable state under its accepted scoped expiry.
        // The issuer must send explicit ABSENT to request immediate removal.
        for (id, prior) in std::mem::take(&mut state.workloads) {
            next.insert(id, prior);
        }
        state.workloads = next;
        state.control_revision = snapshot.control_revision;
        state.request_id = snapshot.request_id;
        state.signed_snapshot_hash = fingerprint;
        self.save(&state)?;
        Ok(state)
    }

    pub fn begin(&self, intent: OperationIntent) -> Result<PendingOperation> {
        let OperationIntent {
            daemon,
            action,
            workload_id,
            generation,
            operation_id,
            operation_sequence,
            request,
            started_at_unix_ms,
        } = intent;
        let mut state = self.load()?;
        if state.pending.is_some() {
            return Err(Error::WorkloadState);
        }
        if daemon == "sandboxd" {
            if operation_sequence == 0
                || operation_sequence <= state.next_operation_sequence
                || operation_sequence > i64::MAX as u64
                || operation_id.len() > 64
                || !operation_id.starts_with(&format!("op-{operation_sequence}-"))
            {
                return Err(Error::WorkloadState);
            }
            state.next_operation_sequence = operation_sequence;
        } else if daemon != "artifactd"
            || operation_sequence != 0
            || operation_id.is_empty()
            || operation_id.len() > 128
        {
            return Err(Error::WorkloadState);
        }
        let operation = PendingOperation {
            daemon: daemon.to_owned(),
            action: action.to_owned(),
            workload_id: workload_id.to_owned(),
            generation,
            operation_id,
            operation_sequence,
            request,
            started_at_unix_ms,
        };
        state.pending = Some(operation.clone());
        self.save(&state)?;
        Ok(operation)
    }

    pub fn finish(
        &self,
        operation_id: &str,
        update: impl FnOnce(&mut WorkloadState) -> Result<()>,
    ) -> Result<()> {
        let mut state = self.load()?;
        if state
            .pending
            .as_ref()
            .is_none_or(|p| p.operation_id != operation_id)
        {
            return Err(Error::WorkloadState);
        }
        update(&mut state)?;
        state.pending = None;
        self.save(&state)
    }

    /// Clears a resolved/retired operation only after the daemon watermark and
    /// authoritative resource inspection have established the retry boundary.
    pub fn resolve_pending(
        &self,
        operation_id: &str,
        accepted_sequence: Option<u64>,
    ) -> Result<()> {
        let mut state = self.load()?;
        if state
            .pending
            .as_ref()
            .is_none_or(|pending| pending.operation_id != operation_id)
        {
            return Err(Error::WorkloadState);
        }
        if let Some(sequence) = accepted_sequence {
            if sequence > i64::MAX as u64 {
                return Err(Error::WorkloadState);
            }
            state.next_operation_sequence = state.next_operation_sequence.max(sequence);
        }
        state.pending = None;
        self.save(&state)
    }

    /// Replace only a terminal artifactd operation with a new durably journaled
    /// token. Callers must establish the old operation's terminal result first.
    pub fn replace_artifact_pending(
        &self,
        expected_operation_id: &str,
        action: &str,
        operation_id: String,
        request: Value,
        now_ms: i64,
    ) -> Result<PendingOperation> {
        let mut state = self.load()?;
        let old = state.pending.as_ref().ok_or(Error::WorkloadState)?;
        if old.daemon != "artifactd"
            || old.operation_id != expected_operation_id
            || operation_id.is_empty()
            || operation_id.len() > 128
            || request.get("version").and_then(Value::as_u64) != Some(3)
            || request
                .pointer("/action/operation")
                .and_then(Value::as_str)
                .is_none()
        {
            return Err(Error::WorkloadState);
        }
        let next = PendingOperation {
            daemon: "artifactd".to_owned(),
            action: action.to_owned(),
            workload_id: old.workload_id.clone(),
            generation: old.generation,
            operation_id,
            operation_sequence: 0,
            request,
            started_at_unix_ms: now_ms,
        };
        state.pending = Some(next.clone());
        self.save(&state)?;
        Ok(next)
    }
}

fn has_resources(resources: &DaemonResources) -> bool {
    resources.artifact_pin_id.is_some()
        || resources.artifact_lease_id.is_some()
        || resources.sandbox_present
        || resources.sandbox_lease_id.is_some()
        || resources.session_generation.is_some()
        || resources.prepared_artifact_id.is_some()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn state_checksum_detects_tampering_and_unknown_versions_fail_closed()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dir = std::fs::canonicalize(std::env::temp_dir())?
            .join(format!("apollo-workload-store-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let store = Store {
            path: dir.join("state"),
        };
        store.save(&WorkloadState::default())?;
        let mut encoded = fs::read(&store.path)?;
        if let Some(byte) = encoded.iter_mut().find(|byte| **byte == b'0') {
            *byte = b'1';
        }
        fs::write(&store.path, encoded)?;
        assert!(store.load().is_err());
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
