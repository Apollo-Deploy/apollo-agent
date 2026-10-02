pub mod events;
pub mod journal;
pub mod mappings;
pub mod sampler;
pub mod workers;
use std::sync::atomic::AtomicU64;

#[derive(Default)]
pub struct Health {
    pub dropped_metric_intervals: AtomicU64,
    pub critical_event_delivery_failures: AtomicU64,
    pub logd_connected: std::sync::atomic::AtomicBool,
    /// Bounded local logd counters; order is defined in local-protocol.md.
    pub logd_counters: [AtomicU64; 9],
}
