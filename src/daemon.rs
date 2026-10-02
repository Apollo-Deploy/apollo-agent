use crate::{
    Error, Result,
    config::Config,
    identity::Identity,
    session::Session,
    store::{durable_write, ensure_directory, private_read},
    telemetry::{
        Health, events,
        journal::Journal,
        mappings,
        sampler::{Sampler, Window},
        workers,
    },
};
use apollo_node_telemetry_protocol::{
    assignment::Assignments,
    decode_canonical,
    wire::{AssignmentSnapshot, EventBatch, client_frame},
};
use ed25519_dalek::VerifyingKey;
use std::{
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};

pub fn public_key(path: &Path) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = private_read(path, 32)?
        .try_into()
        .map_err(|_| Error::Configuration)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Identity)
}
pub async fn run(config_path: &Path) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(Error::Configuration);
    }
    let config = Config::load(config_path)?;
    let authority_watch = crate::session::reload::Watch::capture(config_path, &config)?;
    ensure_directory(&config.state_directory)?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(config.state_directory.join("agent.lock"))?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| Error::Configuration)?;
    let identity = Arc::new(Identity::load(&config.identity)?);
    let control_root = public_key(&config.control_public_key)?;
    let client =
        Session::connect_client(&identity, &config.telemetry_credentials, &config.ca_file).await?;
    let bytes = crate::control::initial(&config, &client, &identity, &control_root).await?;
    let assignments = Assignments::authenticate(
        decode_canonical::<AssignmentSnapshot>(&bytes)?,
        &control_root,
        crate::unix_ms(),
    )?;
    if assignments.snapshot().node_id != identity.node_id
        || assignments.snapshot().credential_generation != identity.credential_generation
        || assignments.snapshot().node_public_key != identity.public_key()?
    {
        return Err(Error::Identity);
    }
    let head_path = config.state_directory.join("assignment-head.pb");
    if !head_path.exists()
        && std::fs::read_dir(&config.state_directory)?
            .any(|entry| entry.is_ok_and(|entry| entry.file_name() != "agent.lock"))
    {
        return Err(Error::Configuration);
    }
    if head_path.exists() {
        let old: AssignmentSnapshot = decode_canonical(&private_read(&head_path, 262_144)?)?;
        let comparison_time = old.issued_at_unix_ms;
        let mut old = Assignments::authenticate(old, &control_root, comparison_time)?;
        old.replace(assignments.clone())?;
    }
    durable_write(&head_path, &bytes)?;
    let mappings = mappings::load(&config.mappings, &assignments)?;
    let assignments = Arc::new(assignments);
    let authority_watch = authority_watch.expires(
        assignments
            .snapshot()
            .expires_at_unix_ms
            .min(identity.expires_at_unix_s.saturating_mul(1_000)),
    );
    // Producer incarnation changes on Agent restart. Kernel boot identity is
    // independently fenced by the runtime mapping manifest.
    let boot = uuid::Uuid::new_v4();
    let session = Session::from_client(
        identity.clone(),
        assignments.clone(),
        public_key(&config.ingest_public_key)?,
        *boot.as_bytes(),
        client,
    )?;
    let live_watch = async {
        if config.assignment_source == crate::config::AssignmentSource::ControlPlane {
            crate::control::watch(
                session.client.clone(),
                identity.clone(),
                control_root,
                (*assignments).clone(),
            )
            .await
        } else {
            std::future::pending::<Result<()>>().await
        }
    };
    let health = Arc::new(Health::default());
    let journal = Arc::new(Mutex::new(Journal::open(
        &config.state_directory.join("events"),
    )?));
    let stop = Arc::new(AtomicBool::new(false));
    let sampler = Sampler::new(mappings);
    let count = sampler.count();
    let (latest_tx, latest_rx) = watch::channel(Arc::new(Window::default()));
    let (event_tx, event_rx) = mpsc::channel(32);
    let sample_thread = start_sampler(
        sampler,
        latest_tx,
        event_tx,
        session.clone(),
        journal.clone(),
        health.clone(),
        stop.clone(),
        Duration::from_millis(config.sample_interval_ms),
    );
    #[cfg(target_os = "linux")]
    let log_thread = {
        let config = config.clone();
        let session = session.clone();
        let health = health.clone();
        let stop = stop.clone();
        let runtime = tokio::runtime::Handle::current();
        std::thread::spawn(move || {
            crate::logd::forward::run(
                &config.logd_socket,
                apollo_telemetry_protocol::local::Peer {
                    uid: config.logd_uid,
                    gid: config.logd_gid,
                },
                session,
                runtime,
                health,
                stop,
            )
        })
    };
    let mut metric_task =
        tokio::spawn(workers::metrics(session.clone(), latest_rx, health.clone()));
    let mut event_task = tokio::spawn(workers::events(
        session.clone(),
        journal.clone(),
        event_rx,
        health.clone(),
    ));
    let mut heartbeat_task =
        tokio::spawn(workers::heartbeat(session.clone(), journal, health, count));
    eprintln!(
        "apollo-agent started; telemetry mappings={count}; lifecycle authority remains Apollo Node V2"
    );
    let outcome = tokio::select! {
        _ = shutdown() => Ok(()),
        _ = &mut metric_task => Err(Error::Transport),
        _ = &mut event_task => Err(Error::Transport),
        _ = &mut heartbeat_task => Err(Error::Transport),
        result = authority_watch.changed() => result,
        result = live_watch => result,
    };
    stop.store(true, Ordering::Relaxed);
    metric_task.abort();
    event_task.abort();
    heartbeat_task.abort();
    tokio::task::spawn_blocking(move || sample_thread.join())
        .await
        .map_err(|_| Error::Configuration)?
        .map_err(|_| Error::Configuration)?;
    #[cfg(target_os = "linux")]
    tokio::task::spawn_blocking(move || log_thread.join())
        .await
        .map_err(|_| Error::Configuration)?
        .map_err(|_| Error::Configuration)?;
    drop(lock);
    outcome
}

#[allow(clippy::too_many_arguments)]
fn start_sampler(
    mut sampler: Sampler,
    latest: watch::Sender<Arc<Window>>,
    best_effort: mpsc::Sender<EventBatch>,
    session: Session,
    journal: Arc<Mutex<Journal>>,
    health: Arc<Health>,
    stop: Arc<AtomicBool>,
    cadence: Duration,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let start = Instant::now();
            match sampler.collect(&health) {
                Ok((window, events)) => {
                    for event in events {
                        let critical = events::critical(&event);
                        let slot = event.assignment_slot as usize;
                        let batch = EventBatch {
                            events: vec![event],
                        };
                        if critical {
                            let result = session.frame(client_frame::Body::Events(batch)).and_then(
                                |frame| {
                                    journal.lock().map_err(|_| Error::Configuration)?.append(
                                        &frame,
                                        session
                                            .assignments()
                                            .snapshot()
                                            .workloads
                                            .get(slot)
                                            .ok_or(Error::Mapping)?,
                                    )
                                },
                            );
                            if result.is_err() {
                                health
                                    .critical_event_delivery_failures
                                    .fetch_add(1, Ordering::Relaxed);
                                eprintln!("critical event journal degraded");
                            }
                        } else {
                            let _bounded_delivery = best_effort.try_send(batch);
                        }
                    }
                    latest.send_replace(Arc::new(window));
                }
                Err(_) => {
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
            }
            std::thread::sleep(cadence.saturating_sub(start.elapsed()));
        }
    })
}
async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
            return;
        }
    }
    let _signal = tokio::signal::ctrl_c().await;
}
