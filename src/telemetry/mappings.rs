//! Immutable, boot-qualified joins supplied by the trusted runtime adapter.
use crate::{Error, Result, cgroup::CgroupHandle, network::Interface, store::private_read};
use apollo_node_telemetry_protocol::assignment::Assignments;
use serde::Deserialize;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    boot_id: String,
    assignment_revision: u64,
    workloads: Vec<Mapping>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    workload_id: String,
    generation: u64,
    desired_workload_sha256: [u8; 32],
    cgroup_path: PathBuf,
    interfaces: Vec<InterfaceBinding>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InterfaceBinding {
    name: String,
    ifindex: u32,
}
pub struct WorkloadCounters {
    pub slot: u32,
    pub cgroup: CgroupHandle,
    pub interfaces: Vec<Interface>,
}

pub fn load(path: &Path, assignments: &Assignments) -> Result<Vec<WorkloadCounters>> {
    let manifest: Manifest =
        serde_json::from_slice(&private_read(path, 524_288)?).map_err(|_| Error::Mapping)?;
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    if manifest.version != 1
        || manifest.boot_id != boot_id.trim()
        || manifest.assignment_revision != assignments.snapshot().revision
        || manifest.workloads.len() > assignments.snapshot().workloads.len()
    {
        return Err(Error::Mapping);
    }
    let mut result = Vec::with_capacity(manifest.workloads.len());
    let mut seen = HashSet::new();
    let mut paths = HashSet::new();
    let mut interfaces = HashSet::new();
    for mapping in manifest.workloads {
        let slot = assignments
            .snapshot()
            .workloads
            .iter()
            .position(|a| {
                a.workload_id == mapping.workload_id
                    && a.generation == mapping.generation
                    && a.desired_workload_sha256 == mapping.desired_workload_sha256
            })
            .ok_or(Error::Mapping)?;
        if !seen.insert(slot)
            || !paths.insert(mapping.cgroup_path.clone())
            || mapping.interfaces.len() > 8
        {
            return Err(Error::Mapping);
        }
        let cgroup = CgroupHandle::open(&mapping.cgroup_path)?;
        let mut known = Vec::with_capacity(mapping.interfaces.len());
        for interface in mapping.interfaces {
            if !interfaces.insert(interface.ifindex) {
                return Err(Error::Mapping);
            }
            known.push(Interface::open(&interface.name, interface.ifindex)?);
        }
        result.push(WorkloadCounters {
            slot: slot as u32,
            cgroup,
            interfaces: known,
        });
    }
    Ok(result)
}
