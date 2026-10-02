use crate::{Error, Result};
use rustix::fs::{Mode, OFlags, openat};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

pub struct CgroupHandle {
    root: File,
    directory: File,
    relative: PathBuf,
    device: u64,
    inode: u64,
}
fn open_relative(root: &File, path: &Path) -> Result<File> {
    let mut directory = root.try_clone()?;
    if path.as_os_str().is_empty() {
        return Err(Error::Mapping);
    }
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(Error::Mapping);
        };
        directory = File::from(
            openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::Mapping)?,
        );
    }
    Ok(directory)
}
impl CgroupHandle {
    pub fn open(relative: &Path) -> Result<Self> {
        let root = File::open("/sys/fs/cgroup")?;
        #[cfg(target_os = "linux")]
        if rustix::fs::fstatfs(&root)
            .map_err(|_| Error::Mapping)?
            .f_type as u64
            != 0x6367_7270
        {
            return Err(Error::Mapping);
        }
        if !cfg!(target_os = "linux") {
            return Err(Error::Mapping);
        }
        let directory = open_relative(&root, relative)?;
        let metadata = directory.metadata()?;
        Ok(Self {
            root,
            directory,
            relative: relative.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    pub fn verify_identity(&self) -> Result<()> {
        let metadata = open_relative(&self.root, &self.relative)?.metadata()?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(Error::Mapping);
        }
        Ok(())
    }
    pub fn read_optional(&self, name: &str, scratch: &mut String) -> Result<bool> {
        // Filenames are static kernel interfaces, never remote input.
        if name.contains('/') {
            return Err(Error::Mapping);
        }
        let fd = match openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(false),
            Err(_) => return Err(Error::Counters),
        };
        scratch.clear();
        File::from(fd).take(65_537).read_to_string(scratch)?;
        if scratch.len() > 65_536 {
            return Err(Error::Counters);
        }
        Ok(true)
    }
    pub fn read_required(&self, name: &str, scratch: &mut String) -> Result<()> {
        if !self.read_optional(name, scratch)? {
            return Err(Error::Counters);
        }
        Ok(())
    }
}
