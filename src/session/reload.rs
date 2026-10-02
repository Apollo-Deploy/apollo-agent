//! Restart the telemetry process on atomic authority-file replacement.
//! Workloads and logd remain independent services during this restart.
use crate::{
    Error, Result,
    config::{AssignmentSource, Config},
    store::private_read,
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

pub struct Watch {
    files: Vec<(PathBuf, usize, [u8; 32])>,
    expires_ms: i64,
}
impl Watch {
    pub fn capture(config_path: &Path, config: &Config) -> Result<Self> {
        let inputs = [
            (config_path, 16_384),
            (config.identity.as_path(), 131_072),
            (config.telemetry_credentials.as_path(), 65_536),
            (config.ca_file.as_path(), 65_536),
            (config.control_public_key.as_path(), 32),
            (config.ingest_public_key.as_path(), 32),
            (config.assignments.as_path(), 262_144),
            (config.mappings.as_path(), 524_288),
        ];
        let files = inputs
            .into_iter()
            .filter(|(path, _)| {
                config.assignment_source == AssignmentSource::File
                    || *path != config.assignments.as_path()
            })
            .map(|(path, limit)| {
                Ok((
                    path.to_owned(),
                    limit,
                    Sha256::digest(private_read(path, limit)?).into(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            files,
            expires_ms: i64::MAX,
        })
    }
    pub fn expires(mut self, expires_ms: i64) -> Self {
        self.expires_ms = expires_ms;
        self
    }
    pub async fn changed(self) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if crate::unix_ms() >= self.expires_ms {
                return Err(Error::Reload);
            }
            for (path, limit, expected) in &self.files {
                let current: [u8; 32] = Sha256::digest(private_read(path, *limit)?).into();
                if &current != expected {
                    return Err(Error::Reload);
                }
            }
        }
    }
}
