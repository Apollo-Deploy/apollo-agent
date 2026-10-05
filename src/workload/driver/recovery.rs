use super::operations::finish_artifact;
use super::*;

pub(super) async fn settle_sandbox(
    store: &Store,
    client: &sandboxd::Client,
    identity: &Identity,
    pending: &PendingOperation,
    _direct: Value,
) -> Result<()> {
    let receipt = client
        .operation_receipt(&pending.operation_id, pending.operation_sequence)
        .await?;
    let state = receipt
        .pointer("/body/state")
        .and_then(Value::as_str)
        .ok_or(Error::WorkloadDaemon)?;
    match state {
        "pending" => Ok(()),
        "complete" => {
            let response = receipt
                .pointer("/body/response")
                .cloned()
                .ok_or(Error::WorkloadDaemon)?;
            finish_sandbox(
                store,
                pending,
                &response,
                receipt
                    .pointer("/body/accepted_sequence")
                    .and_then(Value::as_u64),
            )
        }
        "unknown" | "unavailable" => {
            recover_sandbox_unknown(
                store,
                client,
                identity,
                pending,
                state,
                receipt
                    .pointer("/body/accepted_sequence")
                    .and_then(Value::as_u64),
            )
            .await
        }
        _ => Err(Error::WorkloadDaemon),
    }
}

pub(super) async fn recover_pending(
    config: &WorkloadConfig,
    store: &Store,
    identity: &Identity,
    pending: PendingOperation,
) -> Result<()> {
    if pending.daemon == "artifactd" {
        let client = artifactd::Client::from_config(config);
        let client2 = client.clone();
        let operation_id = pending.operation_id.clone();
        let value = tokio::task::spawn_blocking(move || client2.execute_pending(&pending))
            .await
            .map_err(|_| Error::Transport)??;
        return finish_artifact(store, &operation_id, &value);
    }
    let client = sandboxd::Client::from_config(config);
    let receipt = client
        .operation_receipt(&pending.operation_id, pending.operation_sequence)
        .await?;
    let receipt_state = receipt
        .pointer("/body/state")
        .and_then(Value::as_str)
        .ok_or(Error::WorkloadDaemon)?;
    match receipt_state {
        "pending" => Ok(()),
        "complete" => {
            let response = receipt
                .pointer("/body/response")
                .cloned()
                .ok_or(Error::WorkloadDaemon)?;
            finish_sandbox(
                store,
                &pending,
                &response,
                receipt
                    .pointer("/body/accepted_sequence")
                    .and_then(Value::as_u64),
            )
        }
        "unknown" | "unavailable" => {
            recover_sandbox_unknown(
                store,
                &client,
                identity,
                &pending,
                receipt_state,
                receipt
                    .pointer("/body/accepted_sequence")
                    .and_then(Value::as_u64),
            )
            .await
        }
        _ => Err(Error::WorkloadDaemon),
    }
}

async fn recover_sandbox_unknown(
    store: &Store,
    client: &sandboxd::Client,
    identity: &Identity,
    pending: &PendingOperation,
    receipt_state: &str,
    accepted_sequence: Option<u64>,
) -> Result<()> {
    if let Some(response) = inspect_pending_effect(store, client, identity, pending).await? {
        return finish_sandbox(store, pending, &response, accepted_sequence);
    }
    if receipt_state == "unknown" {
        // Unknown is never retry authority by itself. We inspected the daemon's
        // resource state above; replay is the same sequence and exact request,
        // so a late original request is deduplicated by sandboxd's journal.
        let _ = client.execute_pending(pending).await?;
        return Ok(());
    }
    let watermark = accepted_sequence.ok_or(Error::WorkloadDaemon)?;
    store.resolve_pending(&pending.operation_id, Some(watermark))
}

async fn inspect_pending_effect(
    store: &Store,
    client: &sandboxd::Client,
    identity: &Identity,
    pending: &PendingOperation,
) -> Result<Option<Value>> {
    let state = store.load()?;
    let authority = authority_for(&state, &pending.workload_id, pending.generation)?.clone();
    let resources = resources_for(&state, &pending.workload_id, pending.generation)?.clone();
    match pending.action.as_str() {
        "import_image" => {
            let Some(digest) = resources.manifest_digest.as_deref() else {
                return Ok(None);
            };
            Ok(client
                .image_inspect(digest)
                .await?
                .map(|body| json!({"response":"image","body":body})))
        }
        "create_sandbox"
        | "start_sandbox"
        | "stop_sandbox"
        | "destroy_sandbox"
        | "renew_sandbox_lease"
        | "acquire_sandbox_lease" => {
            let Some(id) = resources.sandbox_id.as_deref() else {
                return Ok(None);
            };
            let Some(body) = client.inspect(id).await? else {
                return if pending.action == "destroy_sandbox" {
                    Ok(Some(
                        json!({"response":"destroyed","body":{"sandbox":id,"generation":resources.sandbox_generation}}),
                    ))
                } else {
                    Ok(None)
                };
            };
            validate_sandbox(identity, &authority, &resources, &body)?;
            let session_state = body.pointer("/session/state").and_then(Value::as_str);
            let effect = match pending.action.as_str() {
                "create_sandbox" => true,
                "start_sandbox" => {
                    session_state.is_some_and(|v| v != "TERMINATED" && v != "FAILED")
                }
                "stop_sandbox" => {
                    session_state.is_none()
                        || matches!(session_state, Some("TERMINATED" | "FAILED"))
                }
                "destroy_sandbox" => false,
                "renew_sandbox_lease" => body
                    .pointer("/lease/renewal_sequence")
                    .and_then(Value::as_u64)
                    .is_some_and(|v| {
                        v >= pending
                            .request
                            .pointer("/mutation/sequence")
                            .and_then(Value::as_u64)
                            .unwrap_or(u64::MAX)
                    }),
                "acquire_sandbox_lease" => {
                    body.pointer("/lease/id").and_then(Value::as_str)
                        != pending
                            .request
                            .pointer("/mutation/fence/lease")
                            .and_then(Value::as_str)
                }
                _ => false,
            };
            if effect {
                Ok(Some(json!({"response":"sandbox","body":body})))
            } else {
                Ok(None)
            }
        }
        "start_workload" => {
            let (Some(sandbox_generation), Some(session_generation), Some(lease), Some(exec)) = (
                resources.sandbox_generation,
                resources.session_generation,
                resources.sandbox_lease_id.as_deref(),
                resources.exec_id.as_deref(),
            ) else {
                return Ok(None);
            };
            let fence = fence(
                &pending.workload_id,
                sandbox_generation,
                Some(session_generation),
                lease,
            );
            if client.exec_status(&fence, exec).await?.is_some() {
                Ok(Some(
                    json!({"response":"guest","body":{"result":"acknowledged"}}),
                ))
            } else {
                Ok(None)
            }
        }
        _ => Err(Error::WorkloadState),
    }
}

fn finish_sandbox(
    store: &Store,
    pending: &PendingOperation,
    response: &Value,
    accepted_sequence: Option<u64>,
) -> Result<()> {
    if response.get("response").and_then(Value::as_str) == Some("error") {
        let reason = response
            .pointer("/body/code")
            .and_then(Value::as_str)
            .unwrap_or("DAEMON_REJECTED");
        let reason = safe_reason(reason);
        let now = crate::unix_ms();
        store.finish(&pending.operation_id, |state| {
            if let Some(item) = state.workloads.get_mut(&pending.workload_id) {
                item.failures = item.failures.saturating_add(1);
                item.retry_after_unix_ms = now.saturating_add(retry_delay(item.failures));
            }
            if let Some(sequence) = accepted_sequence {
                state.next_operation_sequence = state.next_operation_sequence.max(sequence);
            }
            if state
                .pending
                .as_ref()
                .is_none_or(|p| p.operation_id != pending.operation_id)
            {
                return Err(Error::WorkloadState);
            }
            state.pending = None;
            Ok(())
        })?;
        let _ = observation::Observation::record(
            store,
            &pending.workload_id,
            ObservedState::Failed,
            ProcessHealth::Unknown,
            &reason,
            now,
        );
        return Ok(());
    }
    store.finish(&pending.operation_id, |state| {
        apply_sandbox_result(state, pending, response)?;
        if let Some(sequence) = accepted_sequence {
            state.next_operation_sequence = state.next_operation_sequence.max(sequence);
        }
        Ok(())
    })
}

fn apply_sandbox_result(
    state: &mut WorkloadState,
    pending: &PendingOperation,
    response: &Value,
) -> Result<()> {
    let resources = resources_mut(state, &pending.workload_id, pending.generation)?;
    match pending.action.as_str() {
        "import_image" => {
            let body = response.get("body").ok_or(Error::WorkloadDaemon)?;
            let digest = body
                .get("digest")
                .and_then(Value::as_str)
                .ok_or(Error::WorkloadDaemon)?;
            if Some(digest) != resources.manifest_digest.as_deref() {
                return Err(Error::WorkloadState);
            }
            resources.sandbox_image_digest = Some(digest.to_owned());
            resources.artifact_lease_id = None;
        }
        "create_sandbox"
        | "start_sandbox"
        | "stop_sandbox"
        | "renew_sandbox_lease"
        | "acquire_sandbox_lease" => {
            if let Some(body) = response.get("body").filter(|v| v.get("lease").is_some()) {
                sync_resource_fields(resources, body)?;
            }
        }
        "destroy_sandbox" => {
            resources.sandbox_present = false;
            resources.session_generation = None;
            resources.sandbox_lease_id = None;
            resources.sandbox_lease_expires_at_unix_ms = 0;
            resources.lease_renewal_sequence = 0;
        }
        "start_workload" => (),
        _ => return Err(Error::WorkloadState),
    }
    Ok(())
}

fn sync_resource_fields(resources: &mut DaemonResources, body: &Value) -> Result<()> {
    resources.sandbox_present = true;
    resources.sandbox_generation = Some(
        body.get("generation")
            .and_then(Value::as_u64)
            .ok_or(Error::WorkloadDaemon)?,
    );
    if let Some(lease) = body.get("lease") {
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
    }
    resources.session_generation = body
        .get("session")
        .and_then(Value::as_object)
        .and_then(|session| session.get("generation"))
        .and_then(Value::as_u64);
    Ok(())
}
