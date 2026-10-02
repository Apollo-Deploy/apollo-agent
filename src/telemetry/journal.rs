//! Small critical-event journal, entirely separate from logd's WAL.
use crate::{
    Error, Result,
    store::{durable_write, ensure_directory, private_read},
};
use apollo_node_telemetry_protocol::{
    decode_canonical,
    wire::{ClientFrame, JournalEvent, WorkloadAssignment},
};
use prost::Message;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub const MAX_ENTRIES: usize = 1_024;
const MAX_ENTRY_BYTES: usize = 2_048;
pub struct Journal {
    path: PathBuf,
}
impl Journal {
    pub fn open(path: &Path) -> Result<Self> {
        ensure_directory(path)?;
        let journal = Self {
            path: path.to_owned(),
        };
        for item in fs::read_dir(path)? {
            let item = item?;
            let name = item.file_name();
            let name = name.to_str().ok_or(Error::Configuration)?;
            if name.starts_with('.') && name.ends_with(".pending") {
                if uuid::Uuid::parse_str(&name[1..name.len() - 8]).is_err() {
                    return Err(Error::Configuration);
                }
                fs::remove_file(item.path())?;
            }
        }
        if journal.entries()?.len() > MAX_ENTRIES {
            return Err(Error::JournalFull);
        }
        Ok(journal)
    }
    pub fn entries(&self) -> Result<Vec<PathBuf>> {
        let mut entries = Vec::new();
        for item in fs::read_dir(&self.path)? {
            let item = item?;
            let name = item.file_name();
            let name = name.to_str().ok_or(Error::Configuration)?;
            if name.starts_with('.') && name.ends_with(".pending") {
                if uuid::Uuid::parse_str(&name[1..name.len() - 8]).is_err() {
                    return Err(Error::Configuration);
                }
                continue;
            }
            if !name.ends_with(".pb")
                || uuid::Uuid::parse_str(&name[..name.len() - 3]).is_err()
                || !item.file_type()?.is_file()
            {
                return Err(Error::Configuration);
            }
            entries.push(item.path());
            if entries.len() > MAX_ENTRIES {
                return Err(Error::JournalFull);
            }
        }
        entries.sort_unstable();
        Ok(entries)
    }
    pub fn append(&self, frame: &ClientFrame, assignment: &WorkloadAssignment) -> Result<()> {
        let id = uuid::Uuid::from_slice(&frame.message_id).map_err(|_| Error::Configuration)?;
        let path = self.path.join(format!("{id}.pb"));
        let bytes = JournalEvent {
            delivery: Some(frame.clone()),
            assignment: Some(assignment.clone()),
        }
        .encode_to_vec();
        if bytes.len() > MAX_ENTRY_BYTES {
            return Err(Error::Configuration);
        }
        if path.exists() {
            if private_read(&path, MAX_ENTRY_BYTES)? != bytes {
                return Err(Error::Configuration);
            }
            return Ok(());
        }
        if self.entries()?.len() >= MAX_ENTRIES {
            return Err(Error::JournalFull);
        }
        durable_write(&path, &bytes)
    }
    pub fn read(&self, path: &Path) -> Result<JournalEvent> {
        if path.parent() != Some(self.path.as_path()) {
            return Err(Error::Configuration);
        }
        Ok(decode_canonical(&private_read(path, MAX_ENTRY_BYTES)?)?)
    }
    pub fn acknowledge(&self, path: &Path) -> Result<()> {
        if path.parent() != Some(self.path.as_path()) {
            return Err(Error::Configuration);
        }
        fs::remove_file(path)?;
        fs::File::open(&self.path)?.sync_all()?;
        Ok(())
    }
}
