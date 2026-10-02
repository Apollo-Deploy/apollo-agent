//! Kernel cgroup v2 facts. Paths come only from exact runtime assignments.
pub mod cpu;
pub mod io;
pub mod memory;
pub mod path;
pub mod pids;
pub mod pressure;
use crate::{Error, Result};
use apollo_node_telemetry_protocol::wire::MetricSample;
pub use path::CgroupHandle;

pub fn value(input: &str, key: &str) -> Result<Option<u64>> {
    let mut result = None;
    for line in input.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() == Some(key) {
            if result.is_some() {
                return Err(Error::Counters);
            }
            result = Some(
                fields
                    .next()
                    .ok_or(Error::Counters)?
                    .parse()
                    .map_err(|_| Error::Counters)?,
            );
            if fields.next().is_some() {
                return Err(Error::Counters);
            }
        }
    }
    Ok(result)
}

pub fn scalar(input: &str) -> Result<u64> {
    input.trim().parse().map_err(|_| Error::Counters)
}
pub fn limit(input: &str) -> Result<Option<u64>> {
    if input.trim() == "max" {
        Ok(None)
    } else {
        scalar(input).map(Some)
    }
}

pub fn sample(handle: &CgroupHandle, slot: u32, scratch: &mut String) -> Result<MetricSample> {
    handle.verify_identity()?;
    let mut sample = MetricSample {
        assignment_slot: slot,
        timestamp_unix_ms: crate::unix_ms(),
        ..MetricSample::default()
    };
    handle.read_required("cpu.stat", scratch)?;
    sample.cpu = Some(cpu::parse(scratch)?);
    handle.read_required("memory.current", scratch)?;
    let current_bytes = scalar(scratch)?;
    handle.read_required("memory.max", scratch)?;
    let memory_limit = limit(scratch)?;
    handle.read_required("memory.stat", scratch)?;
    let anon_bytes = value(scratch, "anon")?;
    let file_bytes = value(scratch, "file")?;
    let events_hierarchical = if handle.read_optional("memory.events.local", scratch)? {
        false
    } else {
        handle.read_required("memory.events", scratch)?;
        true
    };
    sample.memory = Some(memory::parse(
        scratch,
        current_bytes,
        memory_limit,
        anon_bytes,
        file_bytes,
        events_hierarchical,
    )?);
    if handle.read_optional("io.stat", scratch)? {
        sample.io = Some(io::parse(scratch)?);
    }
    if handle.read_optional("pids.current", scratch)? {
        let current = scalar(scratch)?;
        handle.read_required("pids.max", scratch)?;
        let maximum = limit(scratch)?;
        handle.read_required("pids.events", scratch)?;
        sample.pids = Some(pids::parse(scratch, current, maximum)?);
    }
    for (file, target) in [
        ("cpu.pressure", &mut sample.cpu_pressure),
        ("memory.pressure", &mut sample.memory_pressure),
        ("io.pressure", &mut sample.io_pressure),
    ] {
        if handle.read_optional(file, scratch)? {
            *target = Some(pressure::parse(scratch)?);
        }
    }
    handle.verify_identity()?;
    Ok(sample)
}
