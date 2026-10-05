use super::recovery::settle_sandbox;
use super::*;

pub(super) async fn execute_action(
    config: &WorkloadConfig,
    store: &Store,
    identity: &Identity,
    workload_id: &str,
    authority: &WorkloadAuthority,
    action: Action,
    now: i64,
) -> Result<()> {
    let state = store.load()?;
    let resources = resources_for(&state, workload_id, authority.generation)?.clone();
    match action {
        Action::ResolveArtifact => {
            let client = artifactd::Client::from_config(config);
            let action = json!({"operation":"RESOLVE","digest":authority.artifact_digest,"platform":artifact_platform()?});
            let client2 = client.clone();
            let result = tokio::task::spawn_blocking(move || client2.read(action))
                .await
                .map_err(|_| Error::Transport)??;
            let manifest = result
                .get("manifest_digest")
                .and_then(Value::as_str)
                .ok_or(Error::WorkloadDaemon)?;
            if !valid_digest(manifest)
                || result.get("verified").and_then(Value::as_bool) != Some(true)
                || result.get("artifact_digest").and_then(Value::as_str)
                    != Some(authority.artifact_digest.as_str())
            {
                return Err(Error::WorkloadDaemon);
            }
            store.update(|state| {
                let resources = resources_mut(state, workload_id, authority.generation)?;
                resources.artifact_digest = Some(authority.artifact_digest.clone());
                resources.manifest_digest = Some(manifest.to_owned());
                Ok(())
            })
        }
        Action::PlanSandboxId => {
            let id = sandbox_id(&identity.node_id, authority);
            store.update(|state| {
                resources_mut(state, workload_id, authority.generation)?.sandbox_id = Some(id);
                Ok(())
            })
        }
        Action::PinArtifact => {
            let pin = pin_id(identity, authority);
            artifact_mutate(
                config,
                store,
                workload_id,
                authority.generation,
                "pin",
                json!({"operation":"PIN","id":pin,"digest":authority.artifact_digest}),
                now,
            )
            .await
        }
        Action::CreateArtifactLease => {
            let digest = resources
                .manifest_digest
                .as_deref()
                .ok_or(Error::WorkloadState)?;
            artifact_mutate(config, store, workload_id, authority.generation, "lease_create",
                json!({"operation":"LEASE_CREATE","digest":digest,
                    "grantee":{"uid":config.sandboxd_artifact_uid,"gid":config.sandboxd_artifact_gid}}), now).await
        }
        Action::PrepareArtifact => {
            let digest = resources
                .manifest_digest
                .as_deref()
                .ok_or(Error::WorkloadState)?;
            artifact_mutate(
                config,
                store,
                workload_id,
                authority.generation,
                "prepare",
                json!({"operation":"PREPARE","digest":digest,"platform":artifact_platform()?}),
                now,
            )
            .await
        }
        Action::ReleaseArtifactLease => {
            let id = resources
                .artifact_lease_id
                .as_deref()
                .ok_or(Error::WorkloadState)?;
            artifact_mutate(
                config,
                store,
                workload_id,
                authority.generation,
                "lease_release",
                json!({"operation":"LEASE_RELEASE","id":id}),
                now,
            )
            .await
        }
        Action::UnpinArtifact => {
            let id = resources
                .artifact_pin_id
                .as_deref()
                .ok_or(Error::WorkloadState)?;
            artifact_mutate(
                config,
                store,
                workload_id,
                authority.generation,
                "unpin",
                json!({"operation":"UNPIN","id":id}),
                now,
            )
            .await
        }
        Action::ImportImage => {
            let prepared = resources
                .prepared_artifact_id
                .as_deref()
                .ok_or(Error::WorkloadState)?;
            let manifest = resources
                .manifest_digest
                .as_deref()
                .ok_or(Error::WorkloadState)?;
            let lease = resources
                .artifact_lease_id
                .as_deref()
                .ok_or(Error::WorkloadState)?;
            let sandbox_arch = host_platform()?.sandbox;
            sandbox_mutate(
                config,
                store,
                identity,
                workload_id,
                authority.generation,
                "import_image",
                now,
                |operation, sequence| {
                    json!({"request":"image","operation":operation,"operation_sequence":sequence,
                    "command":{"action":"import_prepared","prepared_artifact_id":prepared,
                        "manifest_digest":manifest,"lease_id":lease,"architecture":sandbox_arch}})
                },
            )
            .await?;
            store.update(|state| {
                let resources = resources_mut(state, workload_id, authority.generation)?;
                resources.sandbox_image_digest = Some(manifest.to_owned());
                // sandboxd consumes the one-use artifactd lease during import.
                resources.artifact_lease_id = None;
                Ok(())
            })
        }
        Action::CreateSandbox => {
            let image = resources
                .manifest_digest
                .as_deref()
                .ok_or(Error::WorkloadState)?;
            let architecture = host_platform()?.sandbox;
            let generation = resources.sandbox_generation;
            sandbox_mutate(config, store, identity, workload_id, authority.generation, "create_sandbox", now,
                |operation, sequence| json!({"request":"mutate","operation":operation,"operation_sequence":sequence,
                    "mutation":{"action":"create","sandbox":resources.sandbox_id,
                        "expected_generation":generation,"lease_seconds":config.lease_seconds,
                        "spec":{"architecture":architecture,"image":image,"kernel_profile":authority.kernel_profile,
                            "runtime_profile":authority.runtime_profile,"persistence":"ephemeral",
                            "resources":{"vcpus":authority.resources.vcpus,"memory_mib":authority.resources.memory_mib,
                                "state_disk_mib":authority.resources.state_disk_mib,"host_memory_max_bytes":authority.resources.host_memory_max_bytes,
                                "cpu_quota_us":authority.resources.cpu_quota_us,"cpu_period_us":authority.resources.cpu_period_us,
                                "cpu_profile":null,"cpuset":null,"state_rate_limiter":null},
                            "network":{"mode":"none"},"volumes":[],"environment":{},
                            "lifetimes":{"sandbox_ttl_seconds":31_536_000,"session_max_seconds":31_536_000,"idle_seconds":31_536_000}}}})).await
        }
        Action::StartSandbox | Action::StopSandbox => {
            let fence = make_fence(&resources, action == Action::StartSandbox)?;
            let control = if action == Action::StartSandbox {
                "start"
            } else {
                "stop"
            };
            let name = if action == Action::StartSandbox {
                "start_sandbox"
            } else {
                "stop_sandbox"
            };
            sandbox_mutate(
                config,
                store,
                identity,
                workload_id,
                authority.generation,
                name,
                now,
                |operation, sequence| {
                    json!({"request":"mutate","operation":operation,"operation_sequence":sequence,
                    "mutation":{"action":"session","fence":fence,"control":control}})
                },
            )
            .await
        }
        Action::AcquireSandboxLease | Action::RenewSandboxLease => {
            let renew = action == Action::RenewSandboxLease;
            let fence = make_fence(&resources, false)?;
            let renewal_sequence = resources.lease_renewal_sequence.saturating_add(1);
            let mutation = if renew {
                json!({"action":"renew","fence":fence,"sequence":renewal_sequence,"duration_seconds":config.lease_seconds})
            } else {
                json!({"action":"acquire_lease","fence":fence,"duration_seconds":config.lease_seconds})
            };
            sandbox_mutate(config, store, identity, workload_id, authority.generation,
                if renew { "renew_sandbox_lease" } else { "acquire_sandbox_lease" }, now,
                |operation, sequence| json!({"request":"mutate","operation":operation,"operation_sequence":sequence,"mutation":mutation})).await
        }
        Action::StartWorkload | Action::RestartWorkload => {
            let generation = resources.sandbox_generation.ok_or(Error::WorkloadState)?;
            let session = resources.session_generation.ok_or(Error::WorkloadState)?;
            let lease = resources
                .sandbox_lease_id
                .as_deref()
                .ok_or(Error::WorkloadState)?;
            let fence = fence(workload_id, generation, Some(session), lease);
            let attempt = resources
                .exec_attempt
                .checked_add(1)
                .ok_or(Error::WorkloadState)?;
            let sandbox = resources
                .sandbox_id
                .as_deref()
                .ok_or(Error::WorkloadState)?;
            let exec = format!("{sandbox}-e{attempt}");
            store.update(|state| {
                let r = resources_mut(state, workload_id, authority.generation)?;
                r.exec_attempt = attempt;
                r.exec_id = Some(exec.clone());
                Ok(())
            })?;
            sandbox_mutate(config, store, identity, workload_id, authority.generation, "start_workload", now,
                |operation, sequence| json!({"request":"guest","operation":operation,"operation_sequence":sequence,
                    "fence":fence,"command":{"command":"exec_start","spec":{"id":exec,
                        "argv":authority.argv,"use_image_defaults":authority.use_image_defaults,
                        "cwd":authority.working_directory,"uid":authority.uid,"gid":authority.gid,
                        "supplementary_groups":[],"readonly_root":true,"mounts":[],"max_processes":authority.max_processes,
                        "environment":{},"secret_environment":{},"pty":null,"stdin":"closed","timeout_ms":4_294_967_295u64,
                        "detached":true,"output_policy":"disabled","output_bytes":0}}})).await
        }
        Action::DestroySandbox => {
            let fence = make_fence(&resources, false)?;
            sandbox_mutate(
                config,
                store,
                identity,
                workload_id,
                authority.generation,
                "destroy_sandbox",
                now,
                |operation, sequence| {
                    json!({"request":"mutate","operation":operation,"operation_sequence":sequence,
                    "mutation":{"action":"destroy","fence":fence}})
                },
            )
            .await
        }
        Action::ForgetMissingSandbox => store.update(|state| {
            let r = resources_mut(state, workload_id, authority.generation)?;
            r.sandbox_present = false;
            r.session_generation = None;
            r.sandbox_lease_id = None;
            r.sandbox_lease_expires_at_unix_ms = 0;
            r.lease_renewal_sequence = 0;
            Ok(())
        }),
        Action::ObserveRunning | Action::ObserveStopped | Action::WaitForDaemon => Ok(()),
    }
}

async fn artifact_mutate(
    config: &WorkloadConfig,
    store: &Store,
    workload_id: &str,
    generation: u64,
    action: &str,
    request_action: Value,
    now: i64,
) -> Result<()> {
    let client = artifactd::Client::from_config(config);
    let client2 = client.clone();
    let token = tokio::task::spawn_blocking(move || client2.allocate())
        .await
        .map_err(|_| Error::Transport)??;
    let request =
        json!({"version":ARTIFACT_PROTOCOL_VERSION,"operation_id":token,"action":request_action});
    let operation_id = request
        .get("operation_id")
        .and_then(Value::as_str)
        .ok_or(Error::WorkloadState)?
        .to_owned();
    let pending = store.begin(OperationIntent {
        daemon: "artifactd",
        action: action.to_owned(),
        workload_id: workload_id.to_owned(),
        generation,
        operation_id: operation_id.clone(),
        operation_sequence: 0,
        request,
        started_at_unix_ms: now,
    })?;
    run_artifact_pending(config, store, pending).await
}

pub(super) fn finish_artifact(store: &Store, operation_id: &str, value: &Value) -> Result<()> {
    store.finish(operation_id, |state| {
        let pending = state.pending.clone().ok_or(Error::WorkloadState)?;
        apply_artifact_result(state, &pending, value)
    })
}

pub(super) async fn run_artifact_pending(
    config: &WorkloadConfig,
    store: &Store,
    pending: PendingOperation,
) -> Result<()> {
    let client = artifactd::Client::from_config(config);
    let client2 = client.clone();
    let retry = pending.action == "lease_create_recovery_release";
    let operation = pending.clone();
    let outcome = tokio::task::spawn_blocking(move || client2.execute_pending_outcome(&operation))
        .await
        .map_err(|_| Error::Transport)??;
    match outcome {
        artifactd::OperationOutcome::Complete(value) => {
            finish_artifact(store, &pending.operation_id, &value)
        }
        artifactd::OperationOutcome::Rejected if !retry => {
            finish_artifact_rejected(store, &pending)
        }
        artifactd::OperationOutcome::Rejected | artifactd::OperationOutcome::Interrupted => {
            retry_artifact_pending(config, store, &client, &pending).await
        }
    }
}

async fn retry_artifact_pending(
    _config: &WorkloadConfig,
    store: &Store,
    client: &artifactd::Client,
    pending: &PendingOperation,
) -> Result<()> {
    let token_client = client.clone();
    let operation_id = tokio::task::spawn_blocking(move || token_client.allocate())
        .await
        .map_err(|_| Error::Transport)??;
    let (action, request) = if pending.action == "lease_create" {
        let lease_id = format!("lease_{}", pending.operation_id);
        (
            "lease_create_recovery_release",
            json!({"version":ARTIFACT_PROTOCOL_VERSION,
            "operation_id":operation_id,"action":{"operation":"LEASE_RELEASE","id":lease_id}}),
        )
    } else {
        let mut request = pending.request.clone();
        request["operation_id"] = Value::String(operation_id.clone());
        (pending.action.as_str(), request)
    };
    if request.get("operation_id").and_then(Value::as_str) != Some(operation_id.as_str()) {
        return Err(Error::WorkloadState);
    }
    let replacement = store.replace_artifact_pending(
        &pending.operation_id,
        action,
        operation_id,
        request,
        crate::unix_ms(),
    )?;
    let client2 = client.clone();
    let operation = replacement.clone();
    let outcome = tokio::task::spawn_blocking(move || client2.execute_pending_outcome(&operation))
        .await
        .map_err(|_| Error::Transport)??;
    match outcome {
        artifactd::OperationOutcome::Complete(value) => {
            finish_artifact(store, &replacement.operation_id, &value)
        }
        artifactd::OperationOutcome::Rejected
            if replacement.action != "lease_create_recovery_release" =>
        {
            finish_artifact_rejected(store, &replacement)
        }
        artifactd::OperationOutcome::Rejected | artifactd::OperationOutcome::Interrupted => Ok(()),
    }
}

pub(super) fn finish_artifact_rejected(store: &Store, pending: &PendingOperation) -> Result<()> {
    let now = crate::unix_ms();
    store.finish(&pending.operation_id, |state| {
        if let Some(item) = state.workloads.get_mut(&pending.workload_id) {
            item.failures = item.failures.saturating_add(1);
            item.retry_after_unix_ms = now.saturating_add(retry_delay(item.failures));
        }
        Ok(())
    })?;
    let _ = observation::Observation::record(
        store,
        &pending.workload_id,
        ObservedState::Failed,
        ProcessHealth::Unknown,
        "ARTIFACT_OPERATION_REJECTED",
        now,
    );
    Ok(())
}

fn apply_artifact_result(
    state: &mut WorkloadState,
    pending: &PendingOperation,
    value: &Value,
) -> Result<()> {
    let resources = resources_mut(state, &pending.workload_id, pending.generation)?;
    match pending.action.as_str() {
        "pin" => {
            let id = pending
                .request
                .pointer("/action/id")
                .and_then(Value::as_str)
                .ok_or(Error::WorkloadState)?;
            if value.get("pin_id").and_then(Value::as_str) != Some(id) {
                return Err(Error::WorkloadDaemon);
            }
            resources.artifact_pin_id = Some(id.to_owned());
        }
        "lease_create" => {
            let expected = format!("lease_{}", pending.operation_id);
            if value.get("lease_id").and_then(Value::as_str) != Some(expected.as_str()) {
                return Err(Error::WorkloadDaemon);
            }
            resources.artifact_lease_id = Some(expected);
        }
        "prepare" => {
            let manifest = value
                .get("manifest_digest")
                .and_then(Value::as_str)
                .ok_or(Error::WorkloadDaemon)?;
            if Some(manifest) != resources.manifest_digest.as_deref() {
                return Err(Error::WorkloadDaemon);
            }
            let prepared = value
                .get("prepared_artifact_id")
                .and_then(Value::as_str)
                .ok_or(Error::WorkloadDaemon)?;
            let prepared_digest = value
                .get("prepared_digest")
                .and_then(Value::as_str)
                .ok_or(Error::WorkloadDaemon)?;
            if prepared.is_empty() || !valid_digest(prepared_digest) {
                return Err(Error::WorkloadDaemon);
            }
            resources.prepared_artifact_id = Some(prepared.to_owned());
        }
        "lease_release" => {
            let id = resources
                .artifact_lease_id
                .as_deref()
                .ok_or(Error::WorkloadState)?;
            if value.get("lease_id").and_then(Value::as_str) != Some(id) {
                return Err(Error::WorkloadDaemon);
            }
            resources.artifact_lease_id = None;
        }
        "lease_create_recovery_release" => (),
        "unpin" => {
            let id = resources
                .artifact_pin_id
                .as_deref()
                .ok_or(Error::WorkloadState)?;
            if value.get("pin_id").and_then(Value::as_str) != Some(id) {
                return Err(Error::WorkloadDaemon);
            }
            resources.artifact_pin_id = None;
            resources.prepared_artifact_id = None;
            resources.manifest_digest = None;
            resources.artifact_digest = None;
        }
        _ => return Err(Error::WorkloadState),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Mirrors the durable operation scope and its caller context.
async fn sandbox_mutate<F>(
    config: &WorkloadConfig,
    store: &Store,
    identity: &Identity,
    workload_id: &str,
    generation: u64,
    action: &str,
    now: i64,
    build: F,
) -> Result<()>
where
    F: FnOnce(String, u64) -> Value,
{
    let client = sandboxd::Client::from_config(config);
    let watermark = client.watermark().await?;
    let current = store.load()?;
    if current.next_operation_sequence > watermark {
        return Err(Error::WorkloadState);
    }
    let sequence = watermark
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(Error::WorkloadState)?;
    let opaque = uuid::Uuid::new_v4().simple().to_string();
    let operation_id = format!("op-{sequence}-{opaque}");
    let request = build(operation_id.clone(), sequence);
    let pending = store.begin(OperationIntent {
        daemon: "sandboxd",
        action: action.to_owned(),
        workload_id: workload_id.to_owned(),
        generation,
        operation_id,
        operation_sequence: sequence,
        request,
        started_at_unix_ms: now,
    })?;
    let value = client.execute_pending(&pending).await?;
    settle_sandbox(store, &client, identity, &pending, value).await
}
