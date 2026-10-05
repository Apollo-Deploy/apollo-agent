//! Pure one-step transition selection. Daemon I/O is driven by the caller after journaling.
use super::{
    authority::{DesiredLifecycle, WorkloadAuthority},
    observation::{ObservedState, ProcessHealth},
    store::DaemonResources,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxStatus {
    Missing,
    Stopped,
    Active,
    Transitioning,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Missing,
    Active,
    Transitioning,
    Failed,
    Terminated,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    PlanSandboxId,
    ResolveArtifact,
    PinArtifact,
    CreateArtifactLease,
    PrepareArtifact,
    ImportImage,
    CreateSandbox,
    StartSandbox,
    StartWorkload,
    ObserveRunning,
    RestartWorkload,
    StopSandbox,
    DestroySandbox,
    ForgetMissingSandbox,
    AcquireSandboxLease,
    RenewSandboxLease,
    ReleaseArtifactLease,
    UnpinArtifact,
    ObserveStopped,
    WaitForDaemon,
}

#[derive(Clone, Copy, Debug)]
pub struct Facts {
    pub sandbox: SandboxStatus,
    pub session: SessionStatus,
    pub process: ProcessHealth,
    pub artifact_image_imported: bool,
}

pub fn next_action(
    authority: &WorkloadAuthority,
    authority_expiry_ms: i64,
    resources: &DaemonResources,
    facts: Facts,
    now_ms: i64,
) -> Action {
    if authority.desired == DesiredLifecycle::Absent
        || now_ms >= authority_expiry_ms
        || now_ms >= authority.expires_at_unix_ms
    {
        return cleanup_action(resources, facts, now_ms);
    }
    if resources.artifact_digest.as_deref() != Some(authority.artifact_digest.as_str()) {
        return Action::ResolveArtifact;
    }
    if resources.artifact_pin_id.is_none() {
        return Action::PinArtifact;
    }
    if resources.artifact_lease_id.is_none() && !facts.artifact_image_imported {
        return Action::CreateArtifactLease;
    }
    if resources.prepared_artifact_id.is_none() && !facts.artifact_image_imported {
        return Action::PrepareArtifact;
    }
    if !facts.artifact_image_imported {
        return Action::ImportImage;
    }
    if resources.sandbox_id.is_none() {
        return Action::PlanSandboxId;
    }
    match facts.sandbox {
        SandboxStatus::Unknown | SandboxStatus::Transitioning => return Action::WaitForDaemon,
        SandboxStatus::Failed => {
            if facts.session == SessionStatus::Failed
                && resources.sandbox_lease_id.is_some()
                && resources.sandbox_lease_expires_at_unix_ms > now_ms
            {
                return Action::StopSandbox;
            }
            // sandboxd owns failed VM cleanup. Its destroy contract requires
            // STOPPED metadata, so wait for that transition rather than
            // issuing a mutation that the daemon must reject.
            return Action::WaitForDaemon;
        }
        SandboxStatus::Missing => return Action::CreateSandbox,
        SandboxStatus::Stopped => (),
        SandboxStatus::Active => (),
    }
    if facts.sandbox == SandboxStatus::Stopped {
        if facts.session != SessionStatus::Missing {
            return match facts.session {
                SessionStatus::Active | SessionStatus::Failed
                    if resources.sandbox_lease_id.is_some()
                        && resources.sandbox_lease_expires_at_unix_ms > now_ms =>
                {
                    Action::StopSandbox
                }
                _ => Action::WaitForDaemon,
            };
        }
        if resources.sandbox_lease_id.is_none() {
            return Action::WaitForDaemon;
        }
        if resources.sandbox_lease_expires_at_unix_ms <= now_ms {
            return Action::AcquireSandboxLease;
        }
    }
    if facts.sandbox == SandboxStatus::Active
        && (resources.sandbox_lease_id.is_none()
            || resources.sandbox_lease_expires_at_unix_ms <= now_ms)
    {
        return Action::WaitForDaemon;
    }
    if resources.sandbox_lease_id.is_some()
        && resources.sandbox_lease_expires_at_unix_ms <= now_ms.saturating_add(60_000)
    {
        return Action::RenewSandboxLease;
    }
    if facts.sandbox == SandboxStatus::Stopped {
        return Action::StartSandbox;
    }
    match facts.session {
        SessionStatus::Missing => return Action::StartSandbox,
        SessionStatus::Active => (),
        SessionStatus::Failed if resources.sandbox_lease_expires_at_unix_ms > now_ms => {
            return Action::StopSandbox;
        }
        SessionStatus::Transitioning
        | SessionStatus::Failed
        | SessionStatus::Terminated
        | SessionStatus::Unknown => return Action::WaitForDaemon,
    }
    match facts.process {
        ProcessHealth::Unknown => Action::StartWorkload,
        ProcessHealth::Alive => Action::ObserveRunning,
        ProcessHealth::Exited => Action::RestartWorkload,
    }
}

pub fn cleanup_action(resources: &DaemonResources, facts: Facts, now_ms: i64) -> Action {
    if resources.sandbox_present {
        match facts.sandbox {
            SandboxStatus::Active => {
                if resources.sandbox_lease_id.is_some()
                    && resources.sandbox_lease_expires_at_unix_ms > now_ms
                    && matches!(facts.session, SessionStatus::Active | SessionStatus::Failed)
                {
                    return Action::StopSandbox;
                }
                return Action::WaitForDaemon;
            }
            SandboxStatus::Transitioning | SandboxStatus::Unknown => return Action::WaitForDaemon,
            SandboxStatus::Failed => {
                if facts.session == SessionStatus::Failed
                    && resources.sandbox_lease_id.is_some()
                    && resources.sandbox_lease_expires_at_unix_ms > now_ms
                {
                    return Action::StopSandbox;
                }
                return Action::WaitForDaemon;
            }
            SandboxStatus::Stopped => {
                if facts.session != SessionStatus::Missing {
                    return match facts.session {
                        SessionStatus::Active | SessionStatus::Failed
                            if resources.sandbox_lease_id.is_some()
                                && resources.sandbox_lease_expires_at_unix_ms > now_ms =>
                        {
                            Action::StopSandbox
                        }
                        _ => Action::WaitForDaemon,
                    };
                }
                if resources.sandbox_lease_id.is_none() {
                    return Action::WaitForDaemon;
                }
                if resources.sandbox_lease_expires_at_unix_ms <= now_ms {
                    return Action::AcquireSandboxLease;
                }
                return Action::DestroySandbox;
            }
            SandboxStatus::Missing => return Action::ForgetMissingSandbox,
        }
    }
    if resources.artifact_lease_id.is_some() {
        return Action::ReleaseArtifactLease;
    }
    if resources.artifact_pin_id.is_some() {
        return Action::UnpinArtifact;
    }
    Action::ObserveStopped
}

pub fn observed_state(
    action: Action,
    sandbox: SandboxStatus,
    process: ProcessHealth,
) -> ObservedState {
    match action {
        Action::ResolveArtifact
        | Action::PinArtifact
        | Action::CreateArtifactLease
        | Action::PrepareArtifact
        | Action::ImportImage
        | Action::PlanSandboxId
        | Action::CreateSandbox => ObservedState::Preparing,
        Action::StartSandbox
        | Action::StartWorkload
        | Action::RestartWorkload
        | Action::AcquireSandboxLease
        | Action::RenewSandboxLease => ObservedState::Starting,
        Action::StopSandbox
        | Action::DestroySandbox
        | Action::ForgetMissingSandbox
        | Action::ReleaseArtifactLease
        | Action::UnpinArtifact => ObservedState::Stopping,
        Action::ObserveStopped => ObservedState::Stopped,
        Action::ObserveRunning
            if sandbox == SandboxStatus::Active && process == ProcessHealth::Alive =>
        {
            ObservedState::Running
        }
        Action::WaitForDaemon => ObservedState::Pending,
        _ => ObservedState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::authority::{Resources, WorkloadAuthority};

    fn authority(desired: DesiredLifecycle) -> WorkloadAuthority {
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
            desired,
            desired_hash: [1; 32],
            issued_at_unix_ms: 1,
            expires_at_unix_ms: 10_000,
            resources: Resources {
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
    fn resources() -> DaemonResources {
        DaemonResources::default()
    }

    #[test]
    fn running_advances_one_action_and_requires_a_process_observation() {
        let authority = authority(DesiredLifecycle::Running);
        let facts = Facts {
            sandbox: SandboxStatus::Missing,
            session: SessionStatus::Missing,
            process: ProcessHealth::Unknown,
            artifact_image_imported: false,
        };
        assert_eq!(
            next_action(&authority, 9_000, &resources(), facts, 1),
            Action::ResolveArtifact
        );
        let mut complete = resources();
        complete.artifact_digest = Some(authority.artifact_digest.clone());
        complete.artifact_pin_id = Some("pin".into());
        assert_eq!(
            next_action(&authority, 9_000, &complete, facts, 1),
            Action::CreateArtifactLease
        );
        complete.artifact_lease_id = Some("lease".into());
        assert_eq!(
            next_action(&authority, 9_000, &complete, facts, 1),
            Action::PrepareArtifact
        );
        complete.prepared_artifact_id = Some("prepared".into());
        complete.sandbox_id = Some("apw-abc-g1".into());
        assert_eq!(
            next_action(
                &authority,
                9_000,
                &complete,
                Facts {
                    artifact_image_imported: true,
                    ..facts
                },
                1
            ),
            Action::CreateSandbox
        );
        complete.sandbox_lease_id = Some("lease".into());
        complete.sandbox_lease_expires_at_unix_ms = 100_000;
        assert_eq!(
            next_action(
                &authority,
                9_000,
                &complete,
                Facts {
                    sandbox: SandboxStatus::Active,
                    session: SessionStatus::Active,
                    process: ProcessHealth::Alive,
                    artifact_image_imported: true
                },
                1
            ),
            Action::ObserveRunning
        );
    }

    #[test]
    fn absence_and_expiry_stop_before_destroy_and_keep_pin_until_absence() {
        let authority = authority(DesiredLifecycle::Absent);
        let resources = DaemonResources {
            sandbox_id: Some("sandbox".into()),
            sandbox_present: true,
            sandbox_lease_id: Some("lease".into()),
            sandbox_lease_expires_at_unix_ms: 10_000,
            artifact_lease_id: Some("artifact-lease".into()),
            artifact_pin_id: Some("pin".into()),
            ..Default::default()
        };
        let active = Facts {
            sandbox: SandboxStatus::Active,
            session: SessionStatus::Active,
            process: ProcessHealth::Alive,
            artifact_image_imported: true,
        };
        assert_eq!(
            next_action(&authority, 10_000, &resources, active, 2),
            Action::StopSandbox
        );
        assert_eq!(
            cleanup_action(
                &resources,
                Facts {
                    sandbox: SandboxStatus::Missing,
                    ..active
                },
                2
            ),
            Action::ForgetMissingSandbox
        );
        let mut clean = resources.clone();
        clean.sandbox_present = false;
        clean.sandbox_lease_id = None;
        clean.artifact_lease_id = None;
        assert_eq!(cleanup_action(&clean, active, 2), Action::UnpinArtifact);
        assert_eq!(
            cleanup_action(&DaemonResources::default(), active, 2),
            Action::ObserveStopped
        );
    }

    #[test]
    fn expired_sandbox_lease_waits_for_daemon_stop_then_reacquires_before_destroy() {
        let resources = DaemonResources {
            sandbox_id: Some("sandbox".into()),
            sandbox_present: true,
            sandbox_generation: Some(4),
            sandbox_lease_id: Some("old-lease".into()),
            sandbox_lease_expires_at_unix_ms: 100,
            ..Default::default()
        };
        let active = Facts {
            sandbox: SandboxStatus::Active,
            session: SessionStatus::Active,
            process: ProcessHealth::Unknown,
            artifact_image_imported: false,
        };
        assert_eq!(
            cleanup_action(&resources, active, 101),
            Action::WaitForDaemon
        );
        let stopped = Facts {
            sandbox: SandboxStatus::Stopped,
            session: SessionStatus::Missing,
            ..active
        };
        assert_eq!(
            cleanup_action(&resources, stopped, 101),
            Action::AcquireSandboxLease
        );
        assert_eq!(
            cleanup_action(&resources, stopped, 101),
            Action::AcquireSandboxLease
        );
        let renewed = DaemonResources {
            sandbox_lease_expires_at_unix_ms: 100_000,
            ..resources
        };
        assert_eq!(
            cleanup_action(&renewed, stopped, 101),
            Action::DestroySandbox
        );
    }

    #[test]
    fn no_destroy_or_start_mutation_while_a_session_is_transitioning() {
        let mut authority = authority(DesiredLifecycle::Running);
        let resources = DaemonResources {
            artifact_digest: Some(authority.artifact_digest.clone()),
            artifact_pin_id: Some("p".into()),
            prepared_artifact_id: Some("a".into()),
            sandbox_image_digest: Some("sha256:x".into()),
            sandbox_id: Some("sandbox".into()),
            sandbox_present: true,
            sandbox_generation: Some(1),
            sandbox_lease_id: Some("lease".into()),
            sandbox_lease_expires_at_unix_ms: 100_000,
            ..Default::default()
        };
        assert_eq!(
            next_action(
                &authority,
                9_000,
                &resources,
                Facts {
                    sandbox: SandboxStatus::Active,
                    session: SessionStatus::Transitioning,
                    process: ProcessHealth::Unknown,
                    artifact_image_imported: true,
                },
                1
            ),
            Action::WaitForDaemon
        );
        authority.desired = DesiredLifecycle::Absent;
        let resources = DaemonResources {
            artifact_digest: Some(authority.artifact_digest.clone()),
            artifact_pin_id: Some("p".into()),
            prepared_artifact_id: Some("a".into()),
            sandbox_image_digest: Some("sha256:x".into()),
            sandbox_id: Some("s".into()),
            sandbox_present: true,
            sandbox_lease_id: Some("lease".into()),
            sandbox_lease_expires_at_unix_ms: 100_000,
            ..Default::default()
        };
        assert_eq!(
            cleanup_action(
                &resources,
                Facts {
                    sandbox: SandboxStatus::Stopped,
                    session: SessionStatus::Transitioning,
                    process: ProcessHealth::Unknown,
                    artifact_image_imported: false
                },
                1
            ),
            Action::WaitForDaemon
        );
    }

    #[test]
    fn expiry_is_workload_scoped_and_process_exit_is_not_healthy() {
        let authority = authority(DesiredLifecycle::Running);
        let resources = DaemonResources {
            artifact_digest: Some(authority.artifact_digest.clone()),
            artifact_pin_id: Some("p".into()),
            prepared_artifact_id: Some("a".into()),
            sandbox_image_digest: Some("sha256:x".into()),
            sandbox_id: Some("s".into()),
            sandbox_present: true,
            sandbox_lease_id: Some("lease".into()),
            sandbox_lease_expires_at_unix_ms: 100_000,
            ..Default::default()
        };
        let active = Facts {
            sandbox: SandboxStatus::Active,
            session: SessionStatus::Active,
            process: ProcessHealth::Exited,
            artifact_image_imported: true,
        };
        assert_eq!(
            next_action(&authority, 100, &resources, active, 101),
            Action::StopSandbox
        );
        assert_eq!(
            next_action(&authority, 100_000, &resources, active, 2),
            Action::RestartWorkload
        );
        assert_eq!(
            observed_state(
                Action::ObserveRunning,
                SandboxStatus::Active,
                ProcessHealth::Exited
            ),
            ObservedState::Failed
        );
    }
}
