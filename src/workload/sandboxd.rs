//! sandboxd v2 framed CBOR client. It never implements VM/runtime behavior.
use crate::{Error, Result, config::WorkloadConfig};
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

const MAGIC: &[u8; 4] = b"ASD\0";
const VERSION: u16 = 2;
const HEADER: usize = 20;
const MAX_BODY: usize = 1_048_576;

#[derive(Clone)]
pub struct Client {
    path: PathBuf,
    server_uid: u32,
}

impl Client {
    pub fn from_config(config: &WorkloadConfig) -> Self {
        Self {
            path: config.sandboxd_socket.clone(),
            server_uid: config.sandboxd_server_uid,
        }
    }

    pub async fn call(&self, request: &Value) -> Result<Value> {
        let value = self.call_unchecked(request).await?;
        if value.get("response").and_then(Value::as_str) == Some("error") {
            return Err(Error::WorkloadDaemon);
        }
        Ok(value)
    }

    async fn call_unchecked(&self, request: &Value) -> Result<Value> {
        let future = async {
            let mut stream = UnixStream::connect(&self.path)
                .await
                .map_err(|_| Error::Transport)?;
            verify_peer_uid(&stream, self.server_uid)?;
            let body = encode(request)?;
            let request_id = u64::from_be_bytes(
                uuid::Uuid::new_v4().as_bytes()[..8]
                    .try_into()
                    .map_err(|_| Error::WorkloadDaemon)?,
            );
            let mut header = [0u8; HEADER];
            header[..4].copy_from_slice(MAGIC);
            header[4..6].copy_from_slice(&VERSION.to_be_bytes());
            header[8..12].copy_from_slice(
                &u32::try_from(body.len())
                    .map_err(|_| Error::WorkloadDaemon)?
                    .to_be_bytes(),
            );
            header[12..20].copy_from_slice(&request_id.to_be_bytes());
            stream
                .write_all(&header)
                .await
                .map_err(|_| Error::Transport)?;
            stream
                .write_all(&body)
                .await
                .map_err(|_| Error::Transport)?;
            let mut reply_header = [0u8; HEADER];
            stream
                .read_exact(&mut reply_header)
                .await
                .map_err(|_| Error::Transport)?;
            if &reply_header[..4] != MAGIC
                || u16::from_be_bytes([reply_header[4], reply_header[5]]) != VERSION
                || reply_header[6..8] != [0, 0]
                || u64::from_be_bytes(
                    reply_header[12..20]
                        .try_into()
                        .map_err(|_| Error::WorkloadDaemon)?,
                ) != request_id
            {
                return Err(Error::WorkloadDaemon);
            }
            let len = u32::from_be_bytes(
                reply_header[8..12]
                    .try_into()
                    .map_err(|_| Error::WorkloadDaemon)?,
            ) as usize;
            if len == 0 || len > MAX_BODY {
                return Err(Error::WorkloadDaemon);
            }
            let mut reply = vec![0u8; len];
            stream
                .read_exact(&mut reply)
                .await
                .map_err(|_| Error::Transport)?;
            let value: Value =
                ciborium::de::from_reader(reply.as_slice()).map_err(|_| Error::WorkloadDaemon)?;
            Ok(value)
        };
        timeout(Duration::from_secs(30), future)
            .await
            .map_err(|_| Error::Transport)?
    }

    pub async fn watermark(&self) -> Result<u64> {
        self.call(&json!({"request":"operation_watermark"}))
            .await?
            .pointer("/body/accepted_sequence")
            .and_then(Value::as_u64)
            .ok_or(Error::WorkloadDaemon)
    }

    pub async fn inspect(&self, sandbox: &str) -> Result<Option<Value>> {
        let value = self
            .call_unchecked(&json!({"request":"inspect","sandbox":sandbox}))
            .await?;
        match value.get("response").and_then(Value::as_str) {
            Some("sandbox") => value
                .get("body")
                .cloned()
                .map(Some)
                .ok_or(Error::WorkloadDaemon),
            Some("error")
                if value.pointer("/body/code").and_then(Value::as_str)
                    == Some("SANDBOX_NOT_FOUND") =>
            {
                Ok(None)
            }
            _ => Err(Error::WorkloadDaemon),
        }
    }

    pub async fn operation_receipt(&self, operation: &str, sequence: u64) -> Result<Value> {
        self.call(&json!({"request":"operation_inspect","operation":operation,"operation_sequence":sequence})).await
    }

    pub async fn image_inspect(&self, digest: &str) -> Result<Option<Value>> {
        let value = self
            .call_unchecked(&json!({"request":"image_inspect","digest":digest}))
            .await?;
        match value.get("response").and_then(Value::as_str) {
            Some("image") => value
                .get("body")
                .cloned()
                .map(Some)
                .ok_or(Error::WorkloadDaemon),
            Some("error")
                if value.pointer("/body/code").and_then(Value::as_str)
                    == Some("IMAGE_NOT_FOUND") =>
            {
                Ok(None)
            }
            _ => Err(Error::WorkloadDaemon),
        }
    }

    pub async fn exec_status(&self, fence: &Value, exec: &str) -> Result<Option<bool>> {
        let value = self
            .call_unchecked(&json!({"request":"exec_status","fence":fence,"exec":exec}))
            .await?;
        match value.get("response").and_then(Value::as_str) {
            Some("guest")
                if value.pointer("/body/result").and_then(Value::as_str) == Some("exec_status") =>
            {
                let exit = value.pointer("/body/exit").ok_or(Error::WorkloadDaemon)?;
                Ok(Some(exit.is_null()))
            }
            Some("error")
                if value.pointer("/body/code").and_then(Value::as_str)
                    == Some("EXEC_NOT_FOUND") =>
            {
                Ok(None)
            }
            _ => Err(Error::WorkloadDaemon),
        }
    }

    pub async fn execute_pending(
        &self,
        operation: &super::store::PendingOperation,
    ) -> Result<Value> {
        if operation.daemon != "sandboxd"
            || operation.operation_sequence == 0
            || operation.operation_sequence > i64::MAX as u64
        {
            return Err(Error::WorkloadState);
        }
        self.call_unchecked(&operation.request).await
    }
}

pub fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    ciborium::into_writer(value, &mut body).map_err(|_| Error::WorkloadDaemon)?;
    if body.is_empty() || body.len() > MAX_BODY {
        return Err(Error::WorkloadDaemon);
    }
    Ok(body)
}

#[cfg(target_os = "linux")]
fn verify_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<()> {
    use std::os::fd::AsFd;
    let peer =
        rustix::net::sockopt::socket_peercred(stream.as_fd()).map_err(|_| Error::Transport)?;
    if peer.uid.as_raw() == expected_uid {
        Ok(())
    } else {
        Err(Error::WorkloadDaemon)
    }
}

#[cfg(not(target_os = "linux"))]
fn verify_peer_uid(_: &UnixStream, _: u32) -> Result<()> {
    Err(Error::Configuration)
}
