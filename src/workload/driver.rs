//! Bounded one-step driver for the pure workload transition function.
use super::{
    artifactd,
    authority::WorkloadAuthority,
    observation::{self, ObservedState, ProcessHealth},
    reconcile::{self, Action, Facts, SandboxStatus, SessionStatus},
    sandboxd,
    store::{
        DaemonResources, OperationIntent, PendingOperation, RetiringGeneration, Store,
        StoredWorkload, WorkloadState,
    },
};
use crate::{Error, Result, config::WorkloadConfig, identity::Identity};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ARTIFACT_PROTOCOL_VERSION: u64 = 3;

mod operations;
mod recovery;

pub async fn run_once(config: &WorkloadConfig, store: &Store, identity: &Identity) -> Result<()> {
    if let Some(pending) = store.load()?.pending {
        return recovery::recover_pending(config, store, identity, pending).await;
    }
    let Some(workload) = store.load()?.workloads.into_values().next() else {
        return Ok(());
    };
    let now = crate::unix_ms();
    if workload.retry_after_unix_ms > now {
        return Ok(());
    }
    if let Some(retiring) = workload.retiring.first() {
        return reconcile_retiring(config, store, identity, &workload, retiring.clone(), now).await;
    }
    reconcile_current(config, store, identity, workload, now).await
}

async fn reconcile_retiring(
    config: &WorkloadConfig,
    store: &Store,
    identity: &Identity,
    workload: &StoredWorkload,
    retiring: RetiringGeneration,
    now: i64,
) -> Result<()> {
    let client = sandboxd::Client::from_config(config);
    let (status, session, body) =
        inspect_sandbox(&client, identity, &retiring.authority, &retiring.resources).await?;
    sync_sandbox(
        store,
        &workload.authority.workload_id,
        retiring.authority.generation,
        body.as_ref(),
        status == SandboxStatus::Missing,
    )?;
    let facts = Facts {
        sandbox: status,
        session,
        process: ProcessHealth::Unknown,
        artifact_image_imported: false,
    };
    match reconcile::cleanup_action(&retiring.resources, facts, now) {
        Action::ObserveStopped => {
            store.update(|state| {
                let item = state
                    .workloads
                    .get_mut(&workload.authority.workload_id)
                    .ok_or(Error::WorkloadState)?;
                item.retiring
                    .retain(|item| item.authority.generation != retiring.authority.generation);
                Ok(())
            })?;
            Ok(())
        }
        Action::WaitForDaemon => Ok(()),
        action => {
            operations::execute_action(
                config,
                store,
                identity,
                &workload.authority.workload_id,
                &retiring.authority,
                action,
                now,
            )
            .await
        }
    }
}

async fn reconcile_current(
    config: &WorkloadConfig,
    store: &Store,
    identity: &Identity,
    workload: StoredWorkload,
    now: i64,
) -> Result<()> {
    let authority = &workload.authority;
    if authority.kernel_profile != config.kernel_profile
        || authority.runtime_profile != config.runtime_profile
    {
        return mark_failed(store, &authority.workload_id, "PROFILE_UNSUPPORTED", now);
    }
    let sandbox = sandboxd::Client::from_config(config);
    let (status, session, body) =
        inspect_sandbox(&sandbox, identity, authority, &workload.resources).await?;
    sync_sandbox(
        store,
        &authority.workload_id,
        authority.generation,
        body.as_ref(),
        status == SandboxStatus::Missing,
    )?;
    let state = store.load()?;
    let current = state
        .workloads
        .get(&authority.workload_id)
        .ok_or(Error::WorkloadState)?;
    let image_imported = match current.resources.manifest_digest.as_deref() {
        Some(digest) => {
            let image = sandbox.image_inspect(digest).await?;
            if let Some(image) = image {
                if image.get("digest").and_then(Value::as_str) != Some(digest) {
                    return Err(Error::WorkloadState);
                }
                true
            } else {
                false
            }
        }
        None => false,
    };
    let process = match (
        current.resources.exec_id.as_deref(),
        current.resources.sandbox_generation,
        current.resources.session_generation,
        current.resources.sandbox_lease_id.as_deref(),
    ) {
        (Some(exec), Some(generation), Some(session_generation), Some(lease))
            if session == SessionStatus::Active =>
        {
            let fence = fence(
                &authority.workload_id,
                generation,
                Some(session_generation),
                lease,
            );
            match sandbox.exec_status(&fence, exec).await? {
                Some(true) => ProcessHealth::Alive,
                Some(false) => ProcessHealth::Exited,
                None => ProcessHealth::Unknown,
            }
        }
        _ => ProcessHealth::Unknown,
    };
    let current = store
        .load()?
        .workloads
        .get(&authority.workload_id)
        .cloned()
        .ok_or(Error::WorkloadState)?;
    let facts = Facts {
        sandbox: status,
        session,
        process,
        artifact_image_imported: image_imported,
    };
    let action = reconcile::next_action(
        authority,
        current.authority_expiry_unix_ms,
        &current.resources,
        facts,
        now,
    );
    match action {
        Action::ObserveRunning => {
            store.update(|state| {
                let item = state
                    .workloads
                    .get_mut(&authority.workload_id)
                    .ok_or(Error::WorkloadState)?;
                item.failures = 0;
                item.retry_after_unix_ms = 0;
                Ok(())
            })?;
            observation::Observation::record(
                store,
                &authority.workload_id,
                ObservedState::Running,
                ProcessHealth::Alive,
                "PROCESS_RUNNING",
                now,
            )?;
            Ok(())
        }
        Action::ObserveStopped => {
            observation::Observation::record(
                store,
                &authority.workload_id,
                ObservedState::Stopped,
                ProcessHealth::Unknown,
                "DESIRED_ABSENT",
                now,
            )?;
            Ok(())
        }
        Action::WaitForDaemon => {
            observation::Observation::record(
                store,
                &authority.workload_id,
                ObservedState::Pending,
                process,
                "DAEMON_TRANSITION",
                now,
            )?;
            Ok(())
        }
        action => {
            let observed = reconcile::observed_state(action, status, process);
            let reason = match observed {
                ObservedState::Preparing => "PREPARING",
                ObservedState::Starting => "STARTING",
                ObservedState::Stopping => "STOPPING",
                ObservedState::Failed => "PROCESS_EXITED",
                _ => "RECONCILING",
            };
            observation::Observation::record(
                store,
                &authority.workload_id,
                observed,
                process,
                reason,
                now,
            )?;
            if action == Action::RestartWorkload {
                store.update(|state| {
                    let item = state
                        .workloads
                        .get_mut(&authority.workload_id)
                        .ok_or(Error::WorkloadState)?;
                    item.failures = item.failures.saturating_add(1);
                    let delay = retry_delay(item.failures);
                    item.retry_after_unix_ms = now.saturating_add(delay);
                    Ok(())
                })?;
            }
            operations::execute_action(
                config,
                store,
                identity,
                &authority.workload_id,
                authority,
                action,
                now,
            )
            .await
        }
    }
}

pub(super) fn retry_delay(failures: u32) -> i64 {
    let exponent = failures.saturating_sub(1).min(8);
    (5_000i64.saturating_mul(1i64 << exponent)).min(300_000)
}

pub(super) async fn inspect_sandbox(
    client: &sandboxd::Client,
    identity: &Identity,
    authority: &WorkloadAuthority,
    resources: &DaemonResources,
) -> Result<(SandboxStatus, SessionStatus, Option<Value>)> {
    let Some(id) = resources.sandbox_id.as_deref() else {
        return Ok((SandboxStatus::Missing, SessionStatus::Missing, None));
    };
    let body = client.inspect(id).await?;
    let Some(body) = body else {
        return Ok((SandboxStatus::Missing, SessionStatus::Missing, None));
    };
    validate_sandbox(identity, authority, resources, &body)?;
    let state = body
        .get("state")
        .and_then(Value::as_str)
        .ok_or(Error::WorkloadDaemon)?;
    let session = match body.get("session") {
        None | Some(Value::Null) => SessionStatus::Missing,
        Some(session) => match session.get("state").and_then(Value::as_str) {
            Some("ACTIVE") => SessionStatus::Active,
            Some("FAILED") => SessionStatus::Failed,
            Some("TERMINATED") => SessionStatus::Terminated,
            Some(
                "PREPARING" | "JAILER_STARTING" | "VMM_CONFIGURING" | "VMM_BOOTING"
                | "GUEST_HANDSHAKE" | "PAUSED" | "TERMINATING",
            ) => SessionStatus::Transitioning,
            _ => SessionStatus::Unknown,
        },
    };
    let status = match state {
        "RUNNING" | "GUEST_READY" => SandboxStatus::Active,
        "PAUSED" => SandboxStatus::Transitioning,
        "STOPPED" | "SUSPENDED" => SandboxStatus::Stopped,
        "FAILED" => SandboxStatus::Failed,
        "ABSENT" => SandboxStatus::Missing,
        "CREATING" | "STARTING" | "BOOTING" | "PAUSING" | "SUSPENDING" | "STOPPING"
        | "DESTROYING" => SandboxStatus::Transitioning,
        _ => SandboxStatus::Unknown,
    };
    Ok((status, session, Some(body)))
}

pub(super) fn validate_sandbox(
    identity: &Identity,
    authority: &WorkloadAuthority,
    resources: &DaemonResources,
    body: &Value,
) -> Result<()> {
    let id = resources
        .sandbox_id
        .as_deref()
        .ok_or(Error::WorkloadState)?;
    if id != sandbox_id(&identity.node_id, authority)
        || authority.organization_id != identity.organization_id
        || body.get("id").and_then(Value::as_str) != Some(id)
    {
        return Err(Error::WorkloadState);
    }
    let generation = body
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or(Error::WorkloadDaemon)?;
    if resources
        .sandbox_generation
        .is_some_and(|expected| expected != generation)
    {
        return Err(Error::WorkloadState);
    }
    let spec = body.get("spec").ok_or(Error::WorkloadDaemon)?;
    let expected_image = resources
        .manifest_digest
        .as_deref()
        .ok_or(Error::WorkloadState)?;
    if spec.pointer("/image").and_then(Value::as_str) != Some(expected_image)
        || spec.pointer("/kernel_profile").and_then(Value::as_str)
            != Some(authority.kernel_profile.as_str())
        || spec.pointer("/runtime_profile").and_then(Value::as_str)
            != Some(authority.runtime_profile.as_str())
        || spec.pointer("/network/mode").and_then(Value::as_str) != Some("none")
        || !spec
            .get("volumes")
            .is_some_and(|value| value.as_array().is_some_and(Vec::is_empty))
        || !spec
            .get("environment")
            .is_some_and(|value| value.as_object().is_some_and(serde_json::Map::is_empty))
        || spec.pointer("/resources/vcpus").and_then(Value::as_u64)
            != Some(u64::from(authority.resources.vcpus))
        || spec
            .pointer("/resources/memory_mib")
            .and_then(Value::as_u64)
            != Some(u64::from(authority.resources.memory_mib))
        || spec
            .pointer("/resources/state_disk_mib")
            .and_then(Value::as_u64)
            != Some(u64::from(authority.resources.state_disk_mib))
        || spec
            .pointer("/resources/host_memory_max_bytes")
            .and_then(Value::as_u64)
            != Some(authority.resources.host_memory_max_bytes)
        || spec
            .pointer("/resources/cpu_quota_us")
            .and_then(Value::as_u64)
            != Some(u64::from(authority.resources.cpu_quota_us))
        || spec
            .pointer("/resources/cpu_period_us")
            .and_then(Value::as_u64)
            != Some(u64::from(authority.resources.cpu_period_us))
        || spec.pointer("/architecture").and_then(Value::as_str) != Some(sandbox_architecture()?)
        || spec.get("persistence").and_then(Value::as_str) != Some("ephemeral")
    {
        return Err(Error::WorkloadState);
    }
    Ok(())
}

pub(super) fn sync_sandbox(
    store: &Store,
    workload_id: &str,
    generation: u64,
    body: Option<&Value>,
    absent: bool,
) -> Result<()> {
    store.update(|state| {
        let resources = resources_mut(state, workload_id, generation)?;
        if absent {
            resources.sandbox_present = false;
            resources.session_generation = None;
            resources.sandbox_lease_id = None;
            resources.sandbox_lease_expires_at_unix_ms = 0;
            resources.lease_renewal_sequence = 0;
            return Ok(());
        }
        let body = body.ok_or(Error::WorkloadState)?;
        resources.sandbox_present = true;
        resources.sandbox_generation = Some(
            body.get("generation")
                .and_then(Value::as_u64)
                .ok_or(Error::WorkloadDaemon)?,
        );
        let lease = body.get("lease").ok_or(Error::WorkloadDaemon)?;
        resources.sandbox_lease_id = Some(
            lease
                .get("id")
                .and_then(Value::as_str)
                .ok_or(Error::WorkloadDaemon)?
                .to_owned(),
        );
        resources.sandbox_lease_expires_at_unix_ms = i64::try_from(
            lease
                .get("expires_at_unix_ms")
                .and_then(Value::as_u64)
                .ok_or(Error::WorkloadDaemon)?,
        )
        .map_err(|_| Error::WorkloadDaemon)?;
        resources.lease_renewal_sequence = lease
            .get("renewal_sequence")
            .and_then(Value::as_u64)
            .ok_or(Error::WorkloadDaemon)?;
        resources.session_generation = body
            .get("session")
            .and_then(Value::as_object)
            .and_then(|session| session.get("generation"))
            .and_then(Value::as_u64);
        Ok(())
    })
}

pub(super) fn mark_failed(store: &Store, workload_id: &str, reason: &str, now: i64) -> Result<()> {
    store.update(|state| {
        let item = state
            .workloads
            .get_mut(workload_id)
            .ok_or(Error::WorkloadState)?;
        item.failures = item.failures.saturating_add(1);
        item.retry_after_unix_ms = now.saturating_add(retry_delay(item.failures));
        Ok(())
    })?;
    let _ = observation::Observation::record(
        store,
        workload_id,
        ObservedState::Failed,
        ProcessHealth::Unknown,
        reason,
        now,
    );
    Ok(())
}

pub(super) fn resources_for<'a>(
    state: &'a WorkloadState,
    workload_id: &str,
    generation: u64,
) -> Result<&'a DaemonResources> {
    let workload = state
        .workloads
        .get(workload_id)
        .ok_or(Error::WorkloadState)?;
    if workload.authority.generation == generation {
        return Ok(&workload.resources);
    }
    workload
        .retiring
        .iter()
        .find(|item| item.authority.generation == generation)
        .map(|item| &item.resources)
        .ok_or(Error::WorkloadState)
}
pub(super) fn resources_mut<'a>(
    state: &'a mut WorkloadState,
    workload_id: &str,
    generation: u64,
) -> Result<&'a mut DaemonResources> {
    let workload = state
        .workloads
        .get_mut(workload_id)
        .ok_or(Error::WorkloadState)?;
    if workload.authority.generation == generation {
        return Ok(&mut workload.resources);
    }
    workload
        .retiring
        .iter_mut()
        .find(|item| item.authority.generation == generation)
        .map(|item| &mut item.resources)
        .ok_or(Error::WorkloadState)
}
pub(super) fn authority_for<'a>(
    state: &'a WorkloadState,
    workload_id: &str,
    generation: u64,
) -> Result<&'a WorkloadAuthority> {
    let workload = state
        .workloads
        .get(workload_id)
        .ok_or(Error::WorkloadState)?;
    if workload.authority.generation == generation {
        return Ok(&workload.authority);
    }
    workload
        .retiring
        .iter()
        .find(|item| item.authority.generation == generation)
        .map(|item| &item.authority)
        .ok_or(Error::WorkloadState)
}
pub(super) fn make_fence(resources: &DaemonResources, starting: bool) -> Result<Value> {
    let generation = resources.sandbox_generation.ok_or(Error::WorkloadState)?;
    let lease = resources
        .sandbox_lease_id
        .as_deref()
        .ok_or(Error::WorkloadState)?;
    let session = if starting {
        None
    } else {
        resources.session_generation
    };
    Ok(fence(
        resources
            .sandbox_id
            .as_deref()
            .ok_or(Error::WorkloadState)?,
        generation,
        session,
        lease,
    ))
}
pub(super) fn fence(
    sandbox: &str,
    generation: u64,
    session_generation: Option<u64>,
    lease: &str,
) -> Value {
    json!({"sandbox":sandbox,"generation":generation,"session_generation":session_generation,"lease":lease})
}
pub(super) fn sandbox_id(node_id: &str, authority: &WorkloadAuthority) -> String {
    let mut hash = Sha256::new();
    hash.update(node_id.as_bytes());
    hash.update([0]);
    hash.update(authority.organization_id.as_bytes());
    hash.update([0]);
    hash.update(authority.workload_id.as_bytes());
    hash.update(authority.generation.to_be_bytes());
    let digest = hash.finalize();
    format!("apw-{}-g{}", hex_prefix(&digest, 32), authority.generation)
}
pub(super) fn pin_id(identity: &Identity, authority: &WorkloadAuthority) -> String {
    let mut hash = Sha256::new();
    hash.update(identity.node_id.as_bytes());
    hash.update([0]);
    hash.update(authority.workload_id.as_bytes());
    hash.update(authority.generation.to_be_bytes());
    format!("apw-pin-{}", hex_prefix(&hash.finalize(), 24))
}
fn hex_prefix(bytes: &[u8], len: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(len);
    for byte in bytes.iter().take(len.div_ceil(2)) {
        out.push(HEX[(byte >> 4) as usize] as char);
        if out.len() < len {
            out.push(HEX[(byte & 15) as usize] as char);
        }
    }
    out
}
pub(super) fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
pub(super) struct HostPlatform {
    artifact: &'static str,
    sandbox: &'static str,
}

pub(super) fn host_platform() -> Result<HostPlatform> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(HostPlatform {
            artifact: "amd64",
            sandbox: "x86_64",
        }),
        "aarch64" => Ok(HostPlatform {
            artifact: "arm64",
            sandbox: "aarch64",
        }),
        _ => Err(Error::WorkloadDaemon),
    }
}
pub(super) fn sandbox_architecture() -> Result<&'static str> {
    Ok(host_platform()?.sandbox)
}
pub(super) fn artifact_platform() -> Result<Value> {
    Ok(json!({"os":"linux","architecture":host_platform()?.artifact,"variant":null}))
}
pub(super) fn safe_reason(code: &str) -> String {
    let normalized: String = code
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
        .take(128)
        .map(char::from)
        .collect();
    if normalized.is_empty() {
        "DAEMON_REJECTED".to_owned()
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::super::authority::DesiredLifecycle;
    use super::*;
    #[test]
    fn sandbox_identity_is_generation_scoped_and_bounded() {
        let node_id = "node_test";
        let mut authority = test_authority();
        let first = sandbox_id(node_id, &authority);
        assert!(first.len() <= 64);
        authority.generation += 1;
        assert_ne!(first, sandbox_id(node_id, &authority));
    }
    fn test_authority() -> WorkloadAuthority {
        WorkloadAuthority {
            organization_id: "org_a".into(),
            project_id: "project_a".into(),
            environment_id: "env_a".into(),
            workload_id: "workload_a".into(),
            placement_id: "placement_a".into(),
            deployment_id: "deployment_a".into(),
            release_id: "release_a".into(),
            generation: 1,
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
            desired: DesiredLifecycle::Running,
            desired_hash: [0; 32],
            issued_at_unix_ms: 1,
            expires_at_unix_ms: 1000,
            resources: super::super::authority::Resources {
                vcpus: 1,
                memory_mib: 128,
                state_disk_mib: 64,
                host_memory_max_bytes: 134_217_728,
                cpu_quota_us: 1_000,
                cpu_period_us: 100_000,
            },
            argv: vec![],
            use_image_defaults: true,
            uid: 1000,
            gid: 1000,
            max_processes: 32,
            working_directory: "/".into(),
            health_policy_process_alive: true,
            kernel_profile: "k1".into(),
            runtime_profile: "r1".into(),
        }
    }
}
