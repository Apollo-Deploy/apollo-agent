use crate::{Error, Result};
use apollo_node_telemetry_protocol::wire::IoCounters;
pub fn parse(input: &str) -> Result<IoCounters> {
    let mut counters = IoCounters::default();
    for line in input.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(device) = fields.next() else {
            continue;
        };
        let Some((major, minor)) = device.split_once(':') else {
            return Err(Error::Counters);
        };
        major.parse::<u32>().map_err(|_| Error::Counters)?;
        minor.parse::<u32>().map_err(|_| Error::Counters)?;
        for field in fields {
            let Some((key, raw)) = field.split_once('=') else {
                return Err(Error::Counters);
            };
            let target = match key {
                "rbytes" => &mut counters.rbytes,
                "wbytes" => &mut counters.wbytes,
                "rios" => &mut counters.rios,
                "wios" => &mut counters.wios,
                _ => continue,
            };
            let value: u64 = raw.parse().map_err(|_| Error::Counters)?;
            *target = target.checked_add(value).ok_or(Error::Counters)?;
        }
    }
    Ok(counters)
}
