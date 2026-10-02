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
        Ok(config)
    }
}
