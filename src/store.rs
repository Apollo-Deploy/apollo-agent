//! Private, no-follow file access and crash-durable bounded state writes.
use crate::{Error, Result};
use rustix::fs::OFlags;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

pub fn private_read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(Error::Configuration);
    }
    #[cfg(target_os = "linux")]
    apollo_telemetry_protocol::local::safe_directory(path.parent().ok_or(Error::Configuration)?)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let stat = file.metadata()?;
    if !stat.is_file()
        || stat.nlink() != 1
        || stat.mode() & 0o077 != 0
        || stat.uid() != rustix::process::geteuid().as_raw()
        || stat.len() > maximum as u64
    {
        return Err(Error::Configuration);
    }
    let mut bytes = Vec::with_capacity(stat.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(Error::Configuration);
    }
    Ok(bytes)
}

pub fn private_directory(path: &Path) -> Result<()> {
    let stat = fs::symlink_metadata(path)?;
    if !stat.is_dir()
        || stat.mode() & 0o077 != 0
        || stat.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(Error::Configuration);
    }
    // Resolve parent links too; credential and journal paths cannot escape a
    // private operator-controlled directory through a symlink.
    if fs::canonicalize(path)? != path {
        return Err(Error::Configuration);
    }
    Ok(())
}

pub fn durable_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(Error::Configuration)?;
    private_directory(parent)?;
    let temporary = parent.join(format!(".{}.pending", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _cleanup = fs::remove_file(temporary);
    }
    result
}

pub fn ensure_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::DirBuilder::new().mode(0o700).create(path)?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    private_directory(path)
}
