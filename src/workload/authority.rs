use super::{AUTHORITY_DOMAIN, MAX_AUTHORITY_BYTES, MAX_WORKLOADS, PROTOCOL_MAJOR, wire};
use crate::{Error, Result, identity::Identity};
use apollo_domain::ids::{
    DeploymentId, EnvironmentId, OrganizationId, PlacementId, ProjectId, ReleaseId, WorkloadId,
};
use ed25519_dalek::{Signature, VerifyingKey};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_AUTHORITY_LIFETIME_MS: i64 = 86_400_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredLifecycle {
    Running,
    Absent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Resources {
    pub vcpus: u8,
    pub memory_mib: u32,
    pub state_disk_mib: u32,
    pub host_memory_max_bytes: u64,
    pub cpu_quota_us: u32,
    pub cpu_period_us: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkloadAuthority {
    pub organization_id: String,
    pub project_id: String,
    pub environment_id: String,
    pub workload_id: String,
    pub placement_id: String,
    pub deployment_id: String,
    pub release_id: String,
    pub generation: u64,
    pub artifact_digest: String,
    pub desired: DesiredLifecycle,
    pub desired_hash: [u8; 32],
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub resources: Resources,
    pub argv: Vec<String>,
    pub use_image_defaults: bool,
    pub uid: u32,
    pub gid: u32,
    pub max_processes: u32,
    pub working_directory: String,
    pub health_policy_process_alive: bool,
    pub kernel_profile: String,
    pub runtime_profile: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceptedSnapshot {
    pub request_id: String,
    pub control_revision: u64,
    pub node_id: String,
    pub organization_id: String,
    pub provider_environment: String,
    pub credential_generation: u64,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub workloads: Vec<WorkloadAuthority>,
}

impl AcceptedSnapshot {
    /// Verifies the CP signature and binds every workload to this enrolled node.
    /// `expected_request_id` is set only for a live response, never for a cached head.
    pub fn authenticate(
        snapshot: wire::AuthoritySnapshot,
        root: &VerifyingKey,
        identity: &Identity,
        now_ms: i64,
        expected_request_id: Option<&str>,
    ) -> Result<Self> {
        if snapshot.encode_to_vec().len() > MAX_AUTHORITY_BYTES {
            return Err(Error::Identity);
        }
        let mut unsigned = snapshot.clone();
        unsigned.signature.clear();
        let signature = Signature::from_slice(&snapshot.signature).map_err(|_| Error::Identity)?;
        root.verify_strict(
            &[AUTHORITY_DOMAIN, &unsigned.encode_to_vec()].concat(),
            &signature,
        )
        .map_err(|_| Error::Identity)?;
        if snapshot.protocol_major != PROTOCOL_MAJOR
            || snapshot.request_id.is_empty()
            || snapshot.request_id.len() > 64
            || expected_request_id.is_some_and(|value| value != snapshot.request_id)
            || snapshot.node_id != identity.node_id
            || snapshot.organization_id != identity.organization_id
            || snapshot.provider_environment != identity.provider_environment
            || snapshot.credential_generation != identity.credential_generation
            || snapshot.control_revision == 0
            || snapshot.issued_at_unix_ms <= 0
            || snapshot.issued_at_unix_ms > now_ms.saturating_add(30_000)
            || snapshot.expires_at_unix_ms <= now_ms
            || snapshot.expires_at_unix_ms <= snapshot.issued_at_unix_ms
            || snapshot
                .expires_at_unix_ms
                .saturating_sub(snapshot.issued_at_unix_ms)
                > MAX_AUTHORITY_LIFETIME_MS
            || snapshot.workloads.len() > MAX_WORKLOADS
        {
            return Err(Error::Identity);
        }

        let mut workloads = Vec::with_capacity(snapshot.workloads.len());
        let mut ids = std::collections::BTreeSet::new();
        for workload in &snapshot.workloads {
            validate_workload(workload, &snapshot, now_ms)?;
            if !ids.insert(workload.workload_id.clone()) {
                return Err(Error::Identity);
            }
            workloads.push(to_authority(workload.clone())?);
        }
        Ok(Self {
            request_id: snapshot.request_id,
            control_revision: snapshot.control_revision,
            node_id: snapshot.node_id,
            organization_id: snapshot.organization_id,
            provider_environment: snapshot.provider_environment,
            credential_generation: snapshot.credential_generation,
            issued_at_unix_ms: snapshot.issued_at_unix_ms,
            expires_at_unix_ms: snapshot.expires_at_unix_ms,
            workloads,
        })
    }
}

fn validate_workload(
    workload: &wire::Workload,
    snapshot: &wire::AuthoritySnapshot,
    now_ms: i64,
) -> Result<()> {
    OrganizationId::parse(workload.organization_id.clone()).map_err(|_| Error::Identity)?;
    ProjectId::parse(workload.project_id.clone()).map_err(|_| Error::Identity)?;
    EnvironmentId::parse(workload.environment_id.clone()).map_err(|_| Error::Identity)?;
    WorkloadId::parse(workload.workload_id.clone()).map_err(|_| Error::Identity)?;
    PlacementId::parse(workload.placement_id.clone()).map_err(|_| Error::Identity)?;
    DeploymentId::parse(workload.deployment_id.clone()).map_err(|_| Error::Identity)?;
    ReleaseId::parse(workload.release_id.clone()).map_err(|_| Error::Identity)?;

    let valid_digest = workload
        .artifact_digest
        .strip_prefix("sha256:")
        .is_some_and(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
    let expected_hash = desired_hash(workload);
    let valid_lifecycle = matches!(
        wire::DesiredLifecycle::try_from(workload.desired_lifecycle),
        Ok(wire::DesiredLifecycle::Running | wire::DesiredLifecycle::Absent)
    );
    let Some(resources) = workload.resources.as_ref() else {
        return Err(Error::Identity);
    };
    let memory_bytes = u64::from(resources.memory_mib).checked_mul(1_048_576);
    let resource_valid = (1..=32).contains(&resources.vcpus)
        && (64..=1_048_576).contains(&resources.memory_mib)
        && (1..=1_048_576).contains(&resources.state_disk_mib)
        && memory_bytes.is_some_and(|bytes| resources.host_memory_max_bytes >= bytes)
        && resources.host_memory_max_bytes <= 2_199_023_255_552
        && (1_000..=1_000_000).contains(&resources.cpu_period_us)
        && resources.cpu_quota_us >= 1_000
        && u64::from(resources.cpu_quota_us)
            <= u64::from(resources.vcpus) * u64::from(resources.cpu_period_us);
    let argv_bytes = workload.argv.iter().try_fold(0usize, |sum, arg| {
        if arg.contains('\0') {
            return None;
        }
        sum.checked_add(arg.len())
    });
    let running = workload.desired_lifecycle == wire::DesiredLifecycle::Running as i32;
    let health_valid = match wire::HealthPolicy::try_from(workload.health_policy) {
        Ok(wire::HealthPolicy::ProcessAlive) => running,
        Ok(wire::HealthPolicy::Unspecified) => !running,
        _ => false,
    };
    let state_hash_valid = workload.desired_state_hash.len() == 32
        && expected_hash.as_slice() == workload.desired_state_hash;

    if workload.organization_id != snapshot.organization_id
        || workload.generation == 0
        || workload.generation > i64::MAX as u64
        || !valid_digest
        || !valid_lifecycle
        || !state_hash_valid
        || workload.issued_at_unix_ms <= 0
        || workload.issued_at_unix_ms > now_ms.saturating_add(30_000)
        || workload.expires_at_unix_ms <= now_ms
        || workload.expires_at_unix_ms <= workload.issued_at_unix_ms
        || workload
            .expires_at_unix_ms
            .saturating_sub(workload.issued_at_unix_ms)
            > MAX_AUTHORITY_LIFETIME_MS
        || workload.expires_at_unix_ms > snapshot.expires_at_unix_ms
        || !resource_valid
        || !workload.ports.is_empty()
        || !workload.secret_references.is_empty()
        || !health_valid
        || workload.uid == u32::MAX
        || workload.gid == u32::MAX
        || !(1..=4096).contains(&workload.max_processes)
        || workload.working_directory.is_empty()
        || workload.working_directory.len() > 4096
        || !workload.working_directory.starts_with('/')
        || workload.working_directory.contains('\0')
        || workload.argv.len() > 256
        || argv_bytes.is_none_or(|bytes| bytes > 65_536)
        || (workload.use_image_defaults && !workload.argv.is_empty())
        || (!workload.use_image_defaults && workload.argv.is_empty())
        || (!workload.argv.is_empty() && workload.argv.first().is_some_and(String::is_empty))
        || workload.kernel_profile.is_empty()
        || workload.kernel_profile.len() > 64
        || workload.runtime_profile.is_empty()
        || workload.runtime_profile.len() > 64
        || !profile_id(&workload.kernel_profile)
        || !profile_id(&workload.runtime_profile)
        // Environment values could contain secrets. Phase 1 deliberately has
        // no secret transport, so require image defaults or argv only.
        || !workload.environment.is_empty()
    {
        return Err(Error::Identity);
    }
    Ok(())
}

fn desired_hash(workload: &wire::Workload) -> [u8; 32] {
    let mut canonical = workload.clone();
    canonical.desired_state_hash.clear();
    // Issue/expiry are authority lease metadata, not desired workload state.
    // Excluding them lets Control renew the same generation without changing
    // its fenced execution identity.
    canonical.issued_at_unix_ms = 0;
    canonical.expires_at_unix_ms = 0;
    Sha256::digest(canonical.encode_to_vec()).into()
}

fn profile_id(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn to_authority(workload: wire::Workload) -> Result<WorkloadAuthority> {
    let resources = workload.resources.ok_or(Error::Identity)?;
    let desired = match wire::DesiredLifecycle::try_from(workload.desired_lifecycle) {
        Ok(wire::DesiredLifecycle::Running) => DesiredLifecycle::Running,
        Ok(wire::DesiredLifecycle::Absent) => DesiredLifecycle::Absent,
        _ => return Err(Error::Identity),
    };
    Ok(WorkloadAuthority {
        organization_id: workload.organization_id,
        project_id: workload.project_id,
        environment_id: workload.environment_id,
        workload_id: workload.workload_id,
        placement_id: workload.placement_id,
        deployment_id: workload.deployment_id,
        release_id: workload.release_id,
        generation: workload.generation,
        artifact_digest: workload.artifact_digest,
        desired,
        desired_hash: workload
            .desired_state_hash
            .try_into()
            .map_err(|_| Error::Identity)?,
        issued_at_unix_ms: workload.issued_at_unix_ms,
        expires_at_unix_ms: workload.expires_at_unix_ms,
        resources: Resources {
            vcpus: u8::try_from(resources.vcpus).map_err(|_| Error::Identity)?,
            memory_mib: resources.memory_mib,
            state_disk_mib: resources.state_disk_mib,
            host_memory_max_bytes: resources.host_memory_max_bytes,
            cpu_quota_us: resources.cpu_quota_us,
            cpu_period_us: resources.cpu_period_us,
        },
        argv: workload.argv,
        use_image_defaults: workload.use_image_defaults,
        uid: workload.uid,
        gid: workload.gid,
        max_processes: workload.max_processes,
        working_directory: workload.working_directory,
        health_policy_process_alive: workload.health_policy
            == wire::HealthPolicy::ProcessAlive as i32,
        kernel_profile: workload.kernel_profile,
        runtime_profile: workload.runtime_profile,
    })
}

pub fn decode_snapshot(bytes: &[u8]) -> Result<wire::AuthoritySnapshot> {
    if bytes.is_empty() || bytes.len() > MAX_AUTHORITY_BYTES {
        return Err(Error::Identity);
    }
    let snapshot = wire::AuthoritySnapshot::decode(bytes).map_err(|_| Error::Identity)?;
    if snapshot.encode_to_vec() != bytes {
        return Err(Error::Identity);
    }
    Ok(snapshot)
}

pub fn request(
    identity: &Identity,
    request_id: &str,
    last_control_revision: u64,
    sent_at_unix_ms: i64,
) -> Result<wire::AuthorityRequest> {
    let mut request = wire::AuthorityRequest {
        protocol_major: PROTOCOL_MAJOR,
        request_id: request_id.to_owned(),
        node_id: identity.node_id.clone(),
        organization_id: identity.organization_id.clone(),
        provider_environment: identity.provider_environment.clone(),
        credential_generation: identity.credential_generation,
        last_control_revision,
        sent_at_unix_ms,
        signature: Vec::new(),
    };
    request.signature = identity.sign_bytes(super::REQUEST_DOMAIN, &request.encode_to_vec())?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desired_hash_binds_every_execution_field_but_not_itself() {
        let workload = wire::Workload {
            workload_id: "workload_a".into(),
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
            desired_lifecycle: wire::DesiredLifecycle::Running as i32,
            argv: vec!["/bin/true".into()],
            ..Default::default()
        };
        let expected = desired_hash(&workload);
        let mut signed = workload.clone();
        signed.desired_state_hash = expected.to_vec();
        assert_eq!(desired_hash(&signed), expected);
        signed.argv[0] = "/bin/false".into();
        assert_ne!(desired_hash(&signed), expected);
    }

    #[test]
    fn digest_and_local_profile_names_are_bounded() {
        assert!(profile_id("fc-v1_amd64"));
        assert!(!profile_id("../kernel"));
        let digest = format!("sha256:{}", "0".repeat(64));
        assert_eq!(digest.len(), 71);
    }
}
