use super::{
    Health,
    events::{Previous, derive_into},
    mappings::WorkloadCounters,
};
use crate::{Error, Result, cgroup, network::NetworkTelemetrySource};
use apollo_node_telemetry_protocol::wire::{MetricSample, NetworkCounters, ResourceEvent};
use std::sync::atomic::Ordering;

#[derive(Default)]
pub struct Window {
    pub sequence: u64,
    pub samples: Vec<MetricSample>,
    pub coverage_start_ms: i64,
}
pub struct Sampler {
    mappings: Vec<WorkloadCounters>,
    previous: Vec<Previous>,
    scratch: String,
    sequence: u64,
    degraded: Vec<bool>,
}
impl Sampler {
    pub fn new(mappings: Vec<WorkloadCounters>) -> Self {
        let count = mappings.len();
        Self {
            mappings,
            previous: vec![Previous::default(); count],
            degraded: vec![false; count],
            scratch: String::with_capacity(4096),
            sequence: 0,
        }
    }
    pub fn count(&self) -> usize {
        self.mappings.len()
    }
    pub fn collect(&mut self, health: &Health) -> Result<(Window, Vec<ResourceEvent>)> {
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Counters)?;
        let mut window = Window {
            sequence: self.sequence,
            coverage_start_ms: crate::unix_ms(),
            samples: Vec::with_capacity(self.mappings.len()),
        };
        let mut events = Vec::new();
        for (index, mapping) in self.mappings.iter().enumerate() {
            let sample = (|| {
                let mut sample = cgroup::sample(&mapping.cgroup, mapping.slot, &mut self.scratch)?;
                if !mapping.interfaces.is_empty() {
                    let mut total = NetworkCounters::default();
                    for interface in &mapping.interfaces {
                        let value = interface.sample()?;
                        for (target, value) in [
                            (&mut total.rx_bytes, value.rx_bytes),
                            (&mut total.tx_bytes, value.tx_bytes),
                            (&mut total.rx_packets, value.rx_packets),
                            (&mut total.tx_packets, value.tx_packets),
                            (&mut total.rx_dropped, value.rx_dropped),
                            (&mut total.tx_dropped, value.tx_dropped),
                        ] {
                            *target = target.checked_add(value).ok_or(Error::Counters)?;
                        }
                    }
                    sample.network = Some(total);
                }
                Ok::<_, Error>(sample)
            })();
            match sample {
                Ok(mut sample) => {
                    derive_into(&mut sample, &mut self.previous[index], &mut events);
                    window.samples.push(sample);
                    self.degraded[index] = false;
                }
                Err(_) => {
                    if !self.degraded[index] {
                        eprintln!(
                            "workload counter collection degraded; slot={}",
                            mapping.slot
                        );
                        self.degraded[index] = true;
                    }
                    health
                        .dropped_metric_intervals
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        Ok((window, events))
    }
}
