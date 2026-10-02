//! At most one in-flight request per lane; latest-only metrics, durable events.
use super::{Health, journal::Journal, sampler::Window};
use crate::{Result, session::Session};
use apollo_node_telemetry_protocol::wire::{EventBatch, Heartbeat, MetricBatch, client_frame};
use std::{
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};
use tokio::sync::{mpsc, watch};

pub async fn metrics(
    session: Session,
    mut latest: watch::Receiver<Arc<Window>>,
    health: Arc<Health>,
) -> Result<()> {
    let mut sent = 0_u64;
    loop {
        if latest.changed().await.is_err() {
            return Ok(());
        }
        loop {
            let window = latest.borrow_and_update().clone();
            if window.sequence <= sent {
                break;
            }
            if !session.connected() {
                break;
            }
            let skipped = window.sequence.saturating_sub(sent).saturating_sub(1);
            let mut complete = true;
            for samples in window.samples.chunks(128) {
                let body = client_frame::Body::Metrics(MetricBatch {
                    sequence: window.sequence,
                    samples: samples.to_vec(),
                    coalesced_intervals: skipped,
                    coverage_start_unix_ms: window.coverage_start_ms,
                });
                if session.send(&session.frame(body)?).await.is_err() {
                    complete = false;
                    break;
                }
            }
            if complete {
                health
                    .dropped_metric_intervals
                    .fetch_add(skipped, Ordering::Relaxed);
                sent = window.sequence;
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

pub async fn events(
    session: Session,
    journal: Arc<Mutex<Journal>>,
    mut best_effort: mpsc::Receiver<EventBatch>,
    health: Arc<Health>,
) -> Result<()> {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut cursor = 0;
    loop {
        tokio::select! {
            event = best_effort.recv() => {
                let Some(batch) = event else { return Ok(()); };
                if session.connected() { let _delivery = session.send(&session.frame(client_frame::Body::Events(batch))?).await; }
            }
            _ = tick.tick() => {
                if !session.connected() { continue; }
                let entries = journal.lock().map_err(|_| crate::Error::Configuration)?.entries()?;
                let visits = entries.len().min(4);
                let start = cursor;
                if !entries.is_empty() { cursor = (cursor + visits) % entries.len(); }
                for offset in 0..visits {
                    let entry = &entries[(start + offset) % entries.len()];
                    let stored = journal.lock().map_err(|_| crate::Error::Configuration)?.read(entry)?;
                    let frame = match session.resume_event(stored) {
                        Ok(frame) => frame,
                        Err(_) => {
                            health.critical_event_delivery_failures.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    match session.send(&frame).await {
                        Ok(_) => journal.lock().map_err(|_| crate::Error::Configuration)?.acknowledge(entry)?,
                        Err(_) => {
                            health.critical_event_delivery_failures.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            }
        }
    }
}

pub async fn heartbeat(
    session: Session,
    journal: Arc<Mutex<Journal>>,
    health: Arc<Health>,
    count: usize,
) -> Result<()> {
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let pending = journal
            .lock()
            .map_err(|_| crate::Error::Configuration)?
            .entries()?
            .len();
        let body = Heartbeat {
            agent_version: env!("CARGO_PKG_VERSION").into(),
            active_mappings: count as u32,
            dropped_metric_intervals: health.dropped_metric_intervals.load(Ordering::Relaxed),
            pending_critical_events: pending as u32,
            logd_connected: health.logd_connected.load(Ordering::Relaxed),
            workload_lifecycle: false,
            critical_event_delivery_failures: health
                .critical_event_delivery_failures
                .load(Ordering::Relaxed),
        };
        if session.connected() {
            let _delivery = session
                .send(&session.frame(client_frame::Body::Heartbeat(body))?)
                .await;
        }
    }
}
