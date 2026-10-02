//! Operator entry point. Infrastructure diagnostics never contain payloads/secrets.
use apollo_agent::{
    Error, Result,
    cgroup::{self, CgroupHandle},
};
use std::{path::Path, time::Duration};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = execute().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn execute() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, config] if command == "run" => apollo_agent::daemon::run(Path::new(config)).await,
        [command, name, index, count, cadence] if command == "network" => {
            use apollo_agent::network::NetworkTelemetrySource;
            let count: usize = count.parse().map_err(|_| Error::Configuration)?;
            let cadence: u64 = cadence.parse().map_err(|_| Error::Configuration)?;
            if !(1..=100_000).contains(&count) || !(10..=60_000).contains(&cadence) {
                return Err(Error::Configuration);
            }
            let interface = apollo_agent::network::Interface::open(
                name,
                index.parse().map_err(|_| Error::Configuration)?,
            )?;
            for sample in 0..count {
                let counters = interface.sample()?;
                println!(
                    "{}",
                    serde_json::json!({"rx_bytes":counters.rx_bytes,"tx_bytes":counters.tx_bytes,
                    "rx_packets":counters.rx_packets,"tx_packets":counters.tx_packets,
                    "rx_dropped":counters.rx_dropped,"tx_dropped":counters.tx_dropped})
                );
                if sample + 1 < count {
                    tokio::time::sleep(Duration::from_millis(cadence)).await;
                }
            }
            Ok(())
        }
        [command, path, count, cadence] if command == "sample" => {
            let count: usize = count.parse().map_err(|_| Error::Configuration)?;
            let cadence: u64 = cadence.parse().map_err(|_| Error::Configuration)?;
            if !(1..=100_000).contains(&count) || !(10..=60_000).contains(&cadence) {
                return Err(Error::Configuration);
            }
            let handle = CgroupHandle::open(Path::new(path))?;
            let mut scratch = String::with_capacity(4096);
            let mut previous = apollo_agent::telemetry::events::Previous::default();
            for index in 0..count {
                let mut sample = cgroup::sample(&handle, 0, &mut scratch)?;
                let events = apollo_agent::telemetry::events::derive(&mut sample, &mut previous);
                let cpu = sample.cpu.ok_or(Error::Counters)?;
                let memory = sample.memory.ok_or(Error::Counters)?;
                let io = sample.io.unwrap_or_default();
                let pids = sample.pids.unwrap_or_default();
                println!(
                    "{}",
                    serde_json::json!({"cpu_usec": cpu.usage_usec,
                    "cpu_cores": cpu.core_equivalents, "memory_bytes": memory.current_bytes,
                    "memory_limit": memory.limit_bytes, "oom": memory.oom, "oom_kill": memory.oom_kill,
                    "io_read_bytes": io.rbytes, "io_write_bytes": io.wbytes, "pids": pids.current,
                    "pids_max_events": pids.max_events, "counter_reset": sample.counter_reset,
                    "event_kinds": events.iter().map(|v| v.kind).collect::<Vec<_>>() })
                );
                if index + 1 < count {
                    tokio::time::sleep(Duration::from_millis(cadence)).await;
                }
            }
            Ok(())
        }
        _ => {
            eprintln!(
                "usage: apollo-agent run /private/config.json | sample relative-cgroup count interval-ms"
            );
            Err(Error::Configuration)
        }
    }
}
