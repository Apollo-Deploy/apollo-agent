use super::value;
use crate::{Error, Result};
use apollo_node_telemetry_protocol::wire::CpuCounters;
pub fn parse(input: &str) -> Result<CpuCounters> {
    Ok(CpuCounters {
        usage_usec: value(input, "usage_usec")?.ok_or(Error::Counters)?,
        user_usec: value(input, "user_usec")?,
        system_usec: value(input, "system_usec")?,
        nr_throttled: value(input, "nr_throttled")?,
        throttled_usec: value(input, "throttled_usec")?,
        core_equivalents: None,
    })
}
