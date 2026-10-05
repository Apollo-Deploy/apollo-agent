//! Signed workload authority request/reply channel and observation outbox.
use super::{
    authority::{self, AcceptedSnapshot},
    observation,
    store::Store,
    wire,
};
use crate::{Error, Result, config::WorkloadConfig, identity::Identity};
use async_nats::Client;
use ed25519_dalek::VerifyingKey;
use futures_util::StreamExt;
use prost::Message;
use std::{path::PathBuf, sync::Arc, time::Duration};

const MAX_REPLY_BYTES: usize = 1_048_576;

pub async fn fetch(
    client: &Client,
    identity: &Identity,
    root: &VerifyingKey,
    store: &Store,
) -> Result<AcceptedSnapshot> {
    let old = store.load()?;
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let inbox = format!(
        "_INBOX.apollo_agent.workload.{}.{}.{}",
        identity.node_id, identity.credential_generation, request_id
    );
    let mut subscription = client
        .subscribe(inbox.clone())
        .await
        .map_err(|_| Error::Transport)?;
    let request = authority::request(
        identity,
        &request_id,
        old.control_revision,
        crate::unix_ms(),
    )?;
    let subject = format!(
        "apollo.node.workload.authority.{}.{}",
        identity.node_id, identity.credential_generation
    );
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        client
            .publish_with_reply(subject, inbox, request.encode_to_vec().into())
            .await
            .map_err(|_| Error::Transport)?;
        let reply = subscription.next().await.ok_or(Error::Transport)?;
        if reply.payload.len() > MAX_REPLY_BYTES {
            return Err(Error::WorkloadDaemon);
        }
        let snapshot = authority::decode_snapshot(&reply.payload)?;
        let accepted = AcceptedSnapshot::authenticate(
            snapshot,
            root,
            identity,
            crate::unix_ms(),
            Some(&request_id),
        )?;
        store.accept(accepted.clone(), &reply.payload)?;
        Ok(accepted)
    })
    .await
    .map_err(|_| Error::Transport)?;
    let unsubscribe_result = subscription
        .unsubscribe()
        .await
        .map_err(|_| Error::Transport);
    unsubscribe_result?;
    result
}

pub async fn publish_observations(
    client: &Client,
    identity: &Identity,
    root: &VerifyingKey,
    store: &Store,
) -> Result<()> {
    let state = store.load()?;
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let Some(frame) = observation::frame(&state, identity, &request_id, crate::unix_ms())? else {
        return Ok(());
    };
    let inbox = format!(
        "_INBOX.apollo_agent.workload.{}.{}.obs.{}",
        identity.node_id, identity.credential_generation, request_id
    );
    let mut subscription = client
        .subscribe(inbox.clone())
        .await
        .map_err(|_| Error::Transport)?;
    let subject = format!(
        "apollo.node.workload.observations.{}.{}",
        identity.node_id, identity.credential_generation
    );
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        client
            .publish_with_reply(subject, inbox, frame.encode_to_vec().into())
            .await
            .map_err(|_| Error::Transport)?;
        let reply = subscription.next().await.ok_or(Error::Transport)?;
        if reply.payload.len() > 16_384 {
            return Err(Error::WorkloadDaemon);
        }
        let ack = wire::ObservationAck::decode(reply.payload.as_ref())
            .map_err(|_| Error::WorkloadDaemon)?;
        if ack.encode_to_vec().as_slice() != reply.payload.as_ref() {
            return Err(Error::WorkloadDaemon);
        }
        let highest_sent_revision = frame
            .observations
            .iter()
            .map(|item| item.observation_revision)
            .max()
            .ok_or(Error::WorkloadState)?;
        let revision = observation::accept_ack(
            ack,
            root,
            identity,
            &request_id,
            &state,
            highest_sent_revision,
            crate::unix_ms(),
        )?;
        observation::acknowledge(store, revision)
    })
    .await
    .map_err(|_| Error::Transport)?;
    subscription
        .unsubscribe()
        .await
        .map_err(|_| Error::Transport)?;
    result
}

pub async fn run(
    client: Client,
    identity: Arc<Identity>,
    root: VerifyingKey,
    config: WorkloadConfig,
    state_directory: PathBuf,
) -> Result<()> {
    let store = Store::open(&state_directory)?;
    let mut interval = tokio::time::interval(Duration::from_millis(config.reconcile_interval_ms));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        match fetch(&client, &identity, &root, &store).await {
            Ok(_) => (),
            Err(Error::Transport) => (),
            Err(error) => eprintln!("workload authority rejected: {error}"),
        }
        if let Err(error) = super::run_once(&config, &store, &identity).await {
            eprintln!("workload reconciliation deferred: {error}");
        }
        match publish_observations(&client, &identity, &root, &store).await {
            Ok(()) | Err(Error::Transport) => (),
            Err(error) => eprintln!("workload observation deferred: {error}"),
        }
    }
}
