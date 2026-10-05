use crate::{Error, Result, store::private_read};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentSource {
    #[default]
    File,
    ControlPlane,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub identity: PathBuf,
    pub ca_file: PathBuf,
    pub telemetry_credentials: PathBuf,
    pub control_public_key: PathBuf,
    pub ingest_public_key: PathBuf,
    pub assignments: PathBuf,
    #[serde(default)]
    pub assignment_source: AssignmentSource,
    pub mappings: PathBuf,
    pub state_directory: PathBuf,
    pub logd_socket: PathBuf,
    pub logd_uid: u32,
    pub logd_gid: u32,
    #[serde(default = "default_sample")]
    pub sample_interval_ms: u64,
    #[serde(default)]
    pub workload: Option<WorkloadConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadConfig {
    pub artifactd_socket: PathBuf,
    pub artifactd_server_uid: u32,
    pub sandboxd_socket: PathBuf,
    pub sandboxd_server_uid: u32,
    pub sandboxd_artifact_uid: u32,
    pub sandboxd_artifact_gid: u32,
    pub kernel_profile: String,
    pub runtime_profile: String,
    #[serde(default = "default_reconcile_interval")]
    pub reconcile_interval_ms: u64,
    #[serde(default = "default_lease_seconds")]
    pub lease_seconds: u32,
}

fn default_reconcile_interval() -> u64 {
    5_000
}
fn default_lease_seconds() -> u32 {
    3_600
}

fn default_sample() -> u64 {
    1_000
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self = serde_json::from_slice(&private_read(path, 16_384)?)
            .map_err(|_| Error::Configuration)?;
        if !(100..=60_000).contains(&config.sample_interval_ms)
            || [
                &config.identity,
                &config.ca_file,
                &config.telemetry_credentials,
                &config.control_public_key,
                &config.assignments,
                &config.mappings,
                &config.ingest_public_key,
                &config.state_directory,
                &config.logd_socket,
            ]
            .iter()
            .any(|p| !p.is_absolute())
        {
            return Err(Error::Configuration);
        }
        if let Some(workload) = &config.workload
            && (config.assignment_source != AssignmentSource::ControlPlane
                || !workload.artifactd_socket.is_absolute()
                || !workload.sandboxd_socket.is_absolute()
                || workload.artifactd_socket == workload.sandboxd_socket
                || workload.kernel_profile.is_empty()
                || workload.kernel_profile.len() > 64
                || workload.runtime_profile.is_empty()
                || workload.runtime_profile.len() > 64
                || !workload
                    .kernel_profile
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || !workload
                    .runtime_profile
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || !(1_000..=60_000).contains(&workload.reconcile_interval_ms)
                || !(10..=3_600).contains(&workload.lease_seconds))
        {
            return Err(Error::Configuration);
        }
        Ok(config)
    }
}
