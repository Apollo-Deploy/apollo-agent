//! Existing Apollo enrollment bundle and stable NKey signing identity.
use crate::{Error, Result, store::private_read};
use apollo_domain::ids::NodeId;
use apollo_node_telemetry_protocol::{CLIENT_DOMAIN, wire::ClientFrame};
use nkeys::KeyPair;
use prost::Message;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    version: u32,
    environment: String,
    node_id: String,
    organization_id: String,
    infrastructure_id: String,
    control_url: String,
    credential_generation: u64,
    issued_at_unix_s: i64,
    expires_at_unix_s: i64,
    nats_credentials: String,
    ca_bundle_pem: String,
}
impl Drop for Bundle {
    fn drop(&mut self) {
        self.nats_credentials.zeroize();
    }
}

pub struct Identity {
    pub node_id: String,
    pub credential_generation: u64,
    pub control_url: String,
    pub expires_at_unix_s: i64,
    pub ca_bundle_pem: String,
    key: KeyPair,
}
pub fn credential_key(credentials: &str) -> Result<KeyPair> {
    let mut lines = credentials.lines();
    while let Some(line) = lines.next() {
        if line.trim() == "-----BEGIN USER NKEY SEED-----" {
            let seed = lines.next().ok_or(Error::Identity)?.trim();
            let key = KeyPair::from_seed(seed).map_err(|_| Error::Identity)?;
            if !key.public_key().starts_with('U') {
                return Err(Error::Identity);
            }
            return Ok(key);
        }
    }
    Err(Error::Identity)
}
impl Identity {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = Zeroizing::new(private_read(path, 131_072)?);
        let mut raw: Bundle = serde_json::from_slice(&bytes).map_err(|_| Error::Identity)?;
        NodeId::parse(raw.node_id.clone()).map_err(|_| Error::Identity)?;
        if raw.version != 1
            || !["apollo_cloud", "byoc", "self_hosted"].contains(&raw.environment.as_str())
            || raw.organization_id.is_empty()
            || raw.infrastructure_id.is_empty()
            || !raw.control_url.starts_with("tls://")
            || raw.control_url.len() > 1024
            || raw.control_url.contains(',')
            || raw.credential_generation == 0
            || raw.issued_at_unix_s <= 0
            || raw.issued_at_unix_s > crate::unix_ms() / 1000 + 30
            || raw.expires_at_unix_s <= crate::unix_ms() / 1000
            || raw.ca_bundle_pem.is_empty()
            || raw.ca_bundle_pem.len() > 65_536
        {
            return Err(Error::Identity);
        }
        let credentials = SecretString::from(std::mem::take(&mut raw.nats_credentials));
        let key = credential_key(credentials.expose_secret())?;
        Ok(Self {
            node_id: std::mem::take(&mut raw.node_id),
            credential_generation: raw.credential_generation,
            control_url: std::mem::take(&mut raw.control_url),
            expires_at_unix_s: raw.expires_at_unix_s,
            ca_bundle_pem: std::mem::take(&mut raw.ca_bundle_pem),
            key,
        })
    }
    pub fn public_key(&self) -> Result<[u8; 32]> {
        nkeys::from_public_key(&self.key.public_key())
            .map(|(_, key)| key)
            .map_err(|_| Error::Identity)
    }
    pub fn sign_bytes(&self, domain: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
        self.key
            .sign(&[domain, bytes].concat())
            .map_err(|_| Error::Identity)
    }
    pub fn sign(&self, frame: &mut ClientFrame) -> Result<()> {
        frame.signature.clear();
        frame.signature = self
            .key
            .sign(&[CLIENT_DOMAIN, &frame.encode_to_vec()].concat())
            .map_err(|_| Error::Identity)?;
        Ok(())
    }
}
