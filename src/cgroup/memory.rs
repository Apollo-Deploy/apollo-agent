use super::value;
use crate::{Error, Result};
use apollo_node_telemetry_protocol::wire::MemoryCounters;
pub fn parse(
    input: &str,
    current_bytes: u64,
    limit_bytes: Option<u64>,
    anon_bytes: Option<u64>,
    file_bytes: Option<u64>,
    events_hierarchical: bool,
) -> Result<MemoryCounters> {
    Ok(MemoryCounters {
        current_bytes,
        limit_bytes,
        anon_bytes,
        file_bytes,
        events_hierarchical,
        high: value(input, "high")?.ok_or(Error::Counters)?,
        max: value(input, "max")?.ok_or(Error::Counters)?,
        oom: value(input, "oom")?.ok_or(Error::Counters)?,
        oom_kill: value(input, "oom_kill")?.ok_or(Error::Counters)?,
    })
}
