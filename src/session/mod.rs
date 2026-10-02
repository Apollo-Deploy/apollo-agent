//! One outbound TLS/NKey connection; independent bounded logical channels.
pub mod reload;
use crate::{Error, Result, identity::Identity, store::private_read};
use apollo_node_telemetry_protocol::{
    MAX_FRAME_BYTES, PROTOCOL_MAJOR,
    assignment::Assignments,
    validation::{authenticate_ack, authenticate_client},
    wire::{ClientFrame, DurableAck, client_frame},
};
use async_nats::{Client, ConnectOptions, connection::State};
use ed25519_dalek::VerifyingKey;
use prost::Message;
use std::{path::Path, sync::Arc, time::Duration};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Session {
    pub client: Client,
    identity: Arc<Identity>,
    assignments: Arc<Assignments>,
    root: VerifyingKey,
    boot_id: [u8; 16],
    subject: String,
}
pub fn backoff(attempt: usize) -> Duration {
    let ceiling = 250_u64.saturating_mul(1_u64 << attempt.min(7)).min(30_000);
    let randomness = uuid::Uuid::new_v4().as_u128() as u64;
    Duration::from_millis(ceiling / 2 + randomness % (ceiling / 2 + 1))
}
impl Session {
    pub async fn connect(
        identity: Arc<Identity>,
        assignments: Arc<Assignments>,
        root: VerifyingKey,
        credentials: &Path,
        ca: &Path,
        boot_id: [u8; 16],
    ) -> Result<Self> {
        if assignments.snapshot().node_id != identity.node_id
            || assignments.snapshot().credential_generation != identity.credential_generation
            || assignments.snapshot().node_public_key != identity.public_key()?
            || private_read(ca, 65_536)? != identity.ca_bundle_pem.as_bytes()
        {
            return Err(Error::Identity);
        }
        let client = Self::connect_client(&identity, credentials, ca).await?;
        Self::from_client(identity, assignments, root, boot_id, client)
    }
    pub async fn connect_client(
        identity: &Identity,
        credentials: &Path,
        ca: &Path,
    ) -> Result<Client> {
        if private_read(ca, 65_536)? != identity.ca_bundle_pem.as_bytes() {
            return Err(Error::Identity);
        }
        let credentials = Zeroizing::new(private_read(credentials, 65_536)?);
        let credentials = std::str::from_utf8(&credentials).map_err(|_| Error::Identity)?;
        let options = ConnectOptions::with_credentials(credentials)
            .map_err(|_| Error::Identity)?
            .custom_inbox_prefix(format!(
                "_INBOX.apollo_agent.{}.{}",
                identity.node_id, identity.credential_generation
            ))
            .require_tls(true)
            .add_root_certificates(ca.to_owned())
            .client_capacity(16)
            .subscription_capacity(16)
            .ping_interval(Duration::from_secs(15))
            .request_timeout(Some(Duration::from_secs(5)))
            .connection_timeout(Duration::from_secs(5))
            .reconnect_delay_callback(backoff)
            .max_reconnects(None)
            .retry_on_initial_connect()
            .name("apollo-agent-telemetry");
        let client = options
            .connect(&identity.control_url)
            .await
            .map_err(|_| Error::Transport)?;
        Ok(client)
    }
    pub fn from_client(
        identity: Arc<Identity>,
        assignments: Arc<Assignments>,
        root: VerifyingKey,
        boot_id: [u8; 16],
        client: Client,
    ) -> Result<Self> {
        if assignments.snapshot().node_id != identity.node_id
            || assignments.snapshot().credential_generation != identity.credential_generation
            || assignments.snapshot().node_public_key != identity.public_key()?
        {
            return Err(Error::Identity);
        }
        Ok(Self {
            subject: format!(
                "apollo.telemetry.ingest.{}.{}",
                identity.node_id, identity.credential_generation
            ),
            client,
            identity,
            assignments,
            root,
            boot_id,
        })
    }
    pub fn connected(&self) -> bool {
        self.client.connection_state() == State::Connected
            && self.identity.expires_at_unix_s > crate::unix_ms() / 1000
            && self.assignments.snapshot().expires_at_unix_ms > crate::unix_ms()
    }
    pub fn assignments(&self) -> &Assignments {
        &self.assignments
    }
    pub fn resume_event(
        &self,
        entry: apollo_node_telemetry_protocol::wire::JournalEvent,
    ) -> Result<ClientFrame> {
        let assignment = entry.assignment.ok_or(Error::Configuration)?;
        let delivery = entry.delivery.ok_or(Error::Configuration)?;
        let Some(client_frame::Body::Events(mut batch)) = delivery.body else {
            return Err(Error::Configuration);
        };
        if batch.events.len() != 1 {
            return Err(Error::Configuration);
        }
        let slot = self
            .assignments
            .snapshot()
            .workloads
            .iter()
            .position(|current| {
                current.workload_id == assignment.workload_id
                    && current.placement_id == assignment.placement_id
                    && current.generation == assignment.generation
                    && current.local_workload_id == assignment.local_workload_id
                    && current.desired_workload_sha256 == assignment.desired_workload_sha256
            })
            .ok_or(Error::Mapping)?;
        batch.events[0].assignment_slot = slot as u32;
        let mut frame = self.frame(client_frame::Body::Events(batch))?;
        frame.message_id = delivery.message_id;
        self.identity.sign(&mut frame)?;
        Ok(frame)
    }
    pub fn frame(&self, body: client_frame::Body) -> Result<ClientFrame> {
        let mut frame = ClientFrame {
            protocol_major: PROTOCOL_MAJOR,
            node_id: self.identity.node_id.clone(),
            credential_generation: self.identity.credential_generation,
            assignment_revision: self.assignments.snapshot().revision,
            boot_id: self.boot_id.to_vec(),
            message_id: uuid::Uuid::new_v4().as_bytes().to_vec(),
            sent_at_unix_ms: crate::unix_ms(),
            body: Some(body),
            signature: vec![],
        };
        self.identity.sign(&mut frame)?;
        Ok(frame)
    }
    pub async fn send(&self, frame: &ClientFrame) -> Result<DurableAck> {
        if !self.connected() {
            return Err(Error::Transport);
        }
        // Preserve journal/event/log identities while refreshing transport time.
        let mut frame = frame.clone();
        frame.sent_at_unix_ms = crate::unix_ms();
        self.identity.sign(&mut frame)?;
        let bytes = frame.encode_to_vec();
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(Error::Configuration);
        }
        authenticate_client(&bytes, &self.assignments, crate::unix_ms())?;
        let reply = tokio::time::timeout(
            Duration::from_secs(5),
            self.client.request(self.subject.clone(), bytes.into()),
        )
        .await
        .map_err(|_| Error::Transport)?
        .map_err(|_| Error::Transport)?;
        Ok(authenticate_ack(
            &reply.payload,
            &frame,
            &self.root,
            crate::unix_ms(),
        )?)
    }
}
