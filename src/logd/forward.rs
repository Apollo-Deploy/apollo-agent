use crate::{session::Session, telemetry::Health};
use apollo_node_telemetry_protocol::{
    validation::validate_log,
    wire::{LogBatch, client_frame},
};
use apollo_telemetry_protocol::{
    Descriptor, invalid,
    local::Peer,
    receiver::{DurableSink, Receiver},
    record,
};
use std::{
    io,
    path::Path,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

struct Forwarder {
    session: Session,
    runtime: tokio::runtime::Handle,
    health: Arc<Health>,
}
impl DurableSink for Forwarder {
    fn counters(&mut self, values: [u64; 9]) {
        for (counter, value) in self.health.logd_counters.iter().zip(values) {
            counter.store(value, Ordering::Relaxed);
        }
    }
    fn register(&mut self, descriptor: Descriptor) -> io::Result<()> {
        let authorized = self
            .session
            .assignments()
            .snapshot()
            .workloads
            .iter()
            .any(|a| {
                a.local_workload_id == descriptor.workload.0
                    && a.generation == descriptor.generation
                    && a.log_stream_ids.iter().any(|s| s == &descriptor.stream.0)
            });
        if !authorized {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
    fn accept(&mut self, bytes: &[u8]) -> io::Result<()> {
        // Receiver validates record framing, not customer payload. A batch may
        // contain several streams; retry after a partial remote acceptance is
        // safe because the ingest sink deduplicates stable record identities.
        let mut rest = bytes;
        while !rest.is_empty() {
            let length = record::length(rest)?;
            let (header, payload) = record::decode(rest.get(..length).ok_or_else(invalid)?)?;
            let first = if header.kind == record::RecordKind::Gap {
                apollo_telemetry_protocol::Gap::decode(payload)?.first
            } else {
                header.sequence
            };
            let mut consumed = length;
            let mut last = header.sequence;
            while consumed < rest.len() {
                let next_length = record::length(&rest[consumed..])?;
                let end = consumed.checked_add(next_length).ok_or_else(invalid)?;
                let (next, _) = record::decode(rest.get(consumed..end).ok_or_else(invalid)?)?;
                if next.stream != header.stream || next.generation != header.generation {
                    break;
                }
                consumed = end;
                last = next.sequence;
            }
            let logs = LogBatch {
                stream_id: header.stream.0.to_vec(),
                generation: header.generation,
                first_sequence: first,
                last_sequence: last,
                encoded_records: rest[..consumed].to_vec(),
            };
            validate_log(&logs, self.session.assignments()).map_err(|_| invalid())?;
            let frame = self
                .session
                .frame(client_frame::Body::Logs(logs))
                .map_err(|_| invalid())?;
            self.runtime
                .block_on(self.session.send(&frame))
                .map_err(|_| io::Error::from(io::ErrorKind::NotConnected))?;
            rest = &rest[consumed..];
        }
        Ok(())
    }
}
pub fn run(
    path: &Path,
    peer: Peer,
    session: Session,
    runtime: tokio::runtime::Handle,
    health: Arc<Health>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut forwarder = Forwarder {
        session,
        runtime,
        health: Arc::clone(&health),
    };
    while !stop.load(Ordering::Relaxed) {
        if let Ok(mut receiver) = Receiver::connect(path, peer) {
            health.logd_connected.store(true, Ordering::Relaxed);
            while !stop.load(Ordering::Relaxed) {
                if let Err(error) = receiver.receive(&mut forwarder) {
                    if error.kind() == io::ErrorKind::TimedOut {
                        continue;
                    }
                    break;
                }
            }
        }
        health.logd_connected.store(false, Ordering::Relaxed);
        std::thread::sleep(Duration::from_secs(1));
    }
}
