//! Events derive from counter changes, never from application log text.
use apollo_node_telemetry_protocol::wire::{EventKind, MetricSample, ResourceEvent};

#[derive(Clone, Copy, Default)]
pub struct Previous {
    pub usage: u64,
    pub oom: u64,
    pub oom_kill: u64,
    pub pids_max: u64,
    pub throttled: u64,
    pub instant: Option<std::time::Instant>,
    pub last_throttle_event_ms: i64,
}
pub fn derive(sample: &mut MetricSample, previous: &mut Previous) -> Vec<ResourceEvent> {
    let mut events = Vec::new();
    derive_into(sample, previous, &mut events);
    events
}
pub fn derive_into(
    sample: &mut MetricSample,
    previous: &mut Previous,
    events: &mut Vec<ResourceEvent>,
) {
    let now = std::time::Instant::now();
    let usage = sample.cpu.as_ref().map_or(0, |v| v.usage_usec);
    let oom = sample.memory.as_ref().map_or(0, |v| v.oom);
    let oom_kill = sample.memory.as_ref().map_or(0, |v| v.oom_kill);
    let pids_max = sample.pids.as_ref().map_or(0, |v| v.max_events);
    let throttled = sample
        .cpu
        .as_ref()
        .and_then(|v| v.nr_throttled)
        .unwrap_or(0);
    if let Some(instant) = previous.instant {
        let wall = now.duration_since(instant).as_micros();
        sample.counter_reset = usage < previous.usage
            || oom < previous.oom
            || oom_kill < previous.oom_kill
            || pids_max < previous.pids_max
            || throttled < previous.throttled;
        if let Some(cpu) = &mut sample.cpu {
            cpu.core_equivalents = usage
                .checked_sub(previous.usage)
                .filter(|_| wall > 0)
                .map(|delta| delta as f64 / wall as f64);
        }
        let mut emit = |kind: EventKind, delta: u64| {
            if delta > 0 {
                events.push(ResourceEvent {
                    event_id: uuid::Uuid::new_v4().as_bytes().to_vec(),
                    assignment_slot: sample.assignment_slot,
                    kind: kind as i32,
                    timestamp_unix_ms: sample.timestamp_unix_ms,
                    counter_delta: delta,
                    memory_current: sample.memory.as_ref().map_or(0, |v| v.current_bytes),
                    memory_limit: sample.memory.as_ref().and_then(|v| v.limit_bytes),
                });
            }
        };
        emit(
            EventKind::WorkloadOom,
            oom_kill
                .saturating_sub(previous.oom_kill)
                .max(oom.saturating_sub(previous.oom)),
        );
        emit(
            EventKind::PidLimitReached,
            pids_max.saturating_sub(previous.pids_max),
        );
        if sample
            .timestamp_unix_ms
            .saturating_sub(previous.last_throttle_event_ms)
            >= 30_000
        {
            let delta = throttled.saturating_sub(previous.throttled);
            emit(EventKind::CpuThrottled, delta);
            if delta > 0 {
                previous.last_throttle_event_ms = sample.timestamp_unix_ms;
            }
        }
    }
    *previous = Previous {
        usage,
        oom,
        oom_kill,
        pids_max,
        throttled,
        instant: Some(now),
        last_throttle_event_ms: previous.last_throttle_event_ms,
    };
}
pub fn critical(event: &ResourceEvent) -> bool {
    matches!(
        EventKind::try_from(event.kind),
        Ok(EventKind::WorkloadOom | EventKind::PidLimitReached)
    )
}
