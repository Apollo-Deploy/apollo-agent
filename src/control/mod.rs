//! Live assignments share the telemetry connection and enrollment identity.
use crate::{
    Error, Result,
    config::{AssignmentSource, Config},
    identity::Identity,
    store::private_read,
};
use apollo_node_telemetry_protocol::{
    MAX_FRAME_BYTES, PROTOCOL_MAJOR,
    assignment::Assignments,
    decode_canonical,
    request::{self, REQUEST_DOMAIN},
    wire::{AssignmentRequest, AssignmentSnapshot},
};
use async_nats::Client;
use ed25519_dalek::VerifyingKey;
use futures_util::StreamExt;
use prost::Message;
use std::time::Duration;

pub async fn fetch(client: &Client, identity: &Identity, root: &VerifyingKey) -> Result<Vec<u8>> {
    let nonce = uuid::Uuid::new_v4();
    let inbox = format!(
        "_INBOX.apollo_agent.{}.{}.{}",
        identity.node_id,
        identity.credential_generation,
        nonce.simple()
    );
    let mut subscription = client
        .subscribe(inbox.clone())
        .await
        .map_err(|_| Error::Transport)?;
    let mut request = AssignmentRequest {
        protocol_major: PROTOCOL_MAJOR,
        node_id: identity.node_id.clone(),
        credential_generation: identity.credential_generation,
        request_id: nonce.as_bytes().to_vec(),
        sent_at_unix_ms: crate::unix_ms(),
        signature: Vec::new(),
    };
    request.signature = identity.sign_bytes(REQUEST_DOMAIN, &request.encode_to_vec())?;
    let subject = request::subject(&identity.node_id, identity.credential_generation);
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        client
            .publish_with_reply(subject, inbox, request.encode_to_vec().into())
            .await
            .map_err(|_| Error::Transport)?;
        let reply = subscription.next().await.ok_or(Error::Transport)?;
        if reply.payload.len() > MAX_FRAME_BYTES {
            return Err(Error::Configuration);
        }
        let snapshot: AssignmentSnapshot = decode_canonical(&reply.payload)?;
        let assignment = Assignments::authenticate(snapshot, root, crate::unix_ms())?;
        let snapshot = assignment.snapshot();
        if snapshot.node_id != identity.node_id
            || snapshot.credential_generation != identity.credential_generation
            || snapshot.node_public_key != identity.public_key()?
        {
            return Err(Error::Identity);
        }
        Ok(reply.payload.to_vec())
    })
    .await
    .map_err(|_| Error::Transport)?;
    subscription
        .unsubscribe()
        .await
        .map_err(|_| Error::Transport)?;
    result
}

/// During an outage only a previously accepted, still-valid head is usable.
/// A failed signature or identity check never falls back to cached authority.
pub async fn initial(
    config: &Config,
    client: &Client,
    identity: &Identity,
    root: &VerifyingKey,
) -> Result<Vec<u8>> {
    if config.assignment_source == AssignmentSource::File {
        return private_read(&config.assignments, MAX_FRAME_BYTES);
    }
    match fetch(client, identity, root).await {
        Ok(bytes) => Ok(bytes),
        Err(Error::Transport) => {
            let bytes = private_read(
                &config.state_directory.join("assignment-head.pb"),
                MAX_FRAME_BYTES,
            )?;
            Assignments::authenticate(decode_canonical(&bytes)?, root, crate::unix_ms())?;
            Ok(bytes)
        }
        Err(error) => Err(error),
    }
}

/// A changed head requests a clean restart; logd and runtime are independent.
/// Runtime mapping must be published for the accepted revision before the
/// new Agent incarnation samples it. No manifest is silently retagged.
pub async fn watch(
    client: Client,
    identity: std::sync::Arc<Identity>,
    root: VerifyingKey,
    accepted: Assignments,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        match fetch(&client, &identity, &root).await {
            Ok(bytes) => {
                let next =
                    Assignments::authenticate(decode_canonical(&bytes)?, &root, crate::unix_ms())?;
                let mut fenced = accepted.clone();
                fenced.replace(next.clone())?;
                if next.snapshot() != accepted.snapshot() {
                    return Err(Error::Reload);
                }
            }
            Err(Error::Transport) => {}
            Err(error) => return Err(error),
        }
        if accepted.snapshot().expires_at_unix_ms <= crate::unix_ms() {
            return Err(Error::Reload);
        }
    }
}
