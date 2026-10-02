//! Basic known-interface counters. No eBPF or flow-log inference.
use crate::{Error, Result};
use apollo_node_telemetry_protocol::wire::NetworkCounters;
use std::{fs, path::PathBuf};

pub trait NetworkTelemetrySource {
    fn sample(&self) -> Result<NetworkCounters>;
}

pub struct Interface {
    path: PathBuf,
    ifindex: u32,
}
impl Interface {
    pub fn open(name: &str, ifindex: u32) -> Result<Self> {
        if name.is_empty()
            || name.len() > 15
            || ifindex == 0
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(Error::Mapping);
        }
        let interface = Self {
            path: PathBuf::from("/sys/class/net").join(name),
            ifindex,
        };
        interface.verify()?;
        Ok(interface)
    }
    fn verify(&self) -> Result<()> {
        let actual: u32 = fs::read_to_string(self.path.join("ifindex"))?
            .trim()
            .parse()
            .map_err(|_| Error::Counters)?;
        if actual != self.ifindex {
            return Err(Error::Mapping);
        }
        Ok(())
    }
}
impl NetworkTelemetrySource for Interface {
    fn sample(&self) -> Result<NetworkCounters> {
        self.verify()?;
        let read = |name: &str| -> Result<u64> {
            // These are fixed kernel sysfs files, each a single u64.
            let text = fs::read_to_string(self.path.join("statistics").join(name))?;
            if text.len() > 32 {
                return Err(Error::Counters);
            }
            text.trim().parse().map_err(|_| Error::Counters)
        };
        let result = NetworkCounters {
            rx_bytes: read("rx_bytes")?,
            tx_bytes: read("tx_bytes")?,
            rx_packets: read("rx_packets")?,
            tx_packets: read("tx_packets")?,
            rx_dropped: read("rx_dropped")?,
            tx_dropped: read("tx_dropped")?,
        };
        self.verify()?;
        Ok(result)
    }
}
