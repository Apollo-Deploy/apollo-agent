use crate::{Error, Result};
use apollo_node_telemetry_protocol::wire::{Pressure, PressureCounters};
pub fn parse(input: &str) -> Result<PressureCounters> {
    let mut counters = PressureCounters::default();
    for line in input.lines() {
        let mut fields = line.split_ascii_whitespace();
        let target = match fields.next() {
            Some("some") => &mut counters.some,
            Some("full") => &mut counters.full,
            _ => continue,
        };
        if target.is_some() {
            return Err(Error::Counters);
        }
        let (mut avg10, mut avg60, mut avg300, mut total) = (None, None, None, None);
        for field in fields {
            let Some((key, raw)) = field.split_once('=') else {
                return Err(Error::Counters);
            };
            if key == "total" {
                if total.is_some() {
                    return Err(Error::Counters);
                }
                total = Some(raw.parse().map_err(|_| Error::Counters)?);
            } else {
                let target = match key {
                    "avg10" => &mut avg10,
                    "avg60" => &mut avg60,
                    "avg300" => &mut avg300,
                    _ => continue,
                };
                if target.is_some() {
                    return Err(Error::Counters);
                }
                let value: f64 = raw.parse().map_err(|_| Error::Counters)?;
                if !value.is_finite() || !(0.0..=100.0).contains(&value) {
                    return Err(Error::Counters);
                }
                *target = Some(value);
            }
        }
        *target = Some(Pressure {
            avg10: avg10.ok_or(Error::Counters)?,
            avg60: avg60.ok_or(Error::Counters)?,
            avg300: avg300.ok_or(Error::Counters)?,
            total_usec: total.ok_or(Error::Counters)?,
        });
    }
    if counters.some.is_none() {
        return Err(Error::Counters);
    }
    Ok(counters)
}
