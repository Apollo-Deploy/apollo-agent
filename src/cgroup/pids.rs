use crate::{Error, Result};
use apollo_node_telemetry_protocol::wire::PidCounters;
pub fn parse(input: &str, current: u64, limit: Option<u64>) -> Result<PidCounters> {
    Ok(PidCounters {
        current,
        limit,
        max_events: super::value(input, "max")?.ok_or(Error::Counters)?,
    })
}
