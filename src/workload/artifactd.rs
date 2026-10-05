//! Minimal artifactd v3 SOCK_SEQPACKET client; all artifact work remains in artifactd.
use crate::{Error, Result, config::WorkloadConfig};
#[cfg(target_os = "linux")]
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::AsFd,
    io::Errno,
    net::{
        self, AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
    },
};
use serde_json::{Value, json};
#[cfg(target_os = "linux")]
use std::{
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
};
use std::{path::PathBuf, time::Duration};

const VERSION: u32 = 3;
#[cfg(target_os = "linux")]
const MAX_PACKET: usize = 64 * 1024;
const INTERRUPTED_RESULT: &str =
    "operation interrupted; outcome uncertain; inspect state before retrying with a new token";

pub enum OperationOutcome {
    Complete(Value),
    Rejected,
    Interrupted,
}

#[derive(Clone)]
#[allow(dead_code)] // The non-Linux build keeps the config shape but disables this client.
pub struct Client {
    path: PathBuf,
    server_uid: u32,
}

impl Client {
    pub fn from_config(config: &WorkloadConfig) -> Self {
        Self {
            path: config.artifactd_socket.clone(),
            server_uid: config.artifactd_server_uid,
        }
    }

    pub fn allocate(&self) -> Result<String> {
        let response = self.call(
            "allocation",
            json!({"operation":"OPERATION_ALLOCATE"}),
            Duration::from_secs(30),
        )?;
        let id = response
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or(Error::WorkloadDaemon)?;
        let (epoch, sequence) = id.split_once('_').ok_or(Error::WorkloadDaemon)?;
        if epoch.len() != 32
            || !epoch
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || sequence.len() != 20
            || !sequence.bytes().all(|b| b.is_ascii_digit())
            || sequence.parse::<u64>().ok().filter(|n| *n > 0).is_none()
        {
            return Err(Error::WorkloadDaemon);
        }
        Ok(id.to_owned())
    }

    pub fn read(&self, action: Value) -> Result<Value> {
        let id = format!("read{}", uuid::Uuid::new_v4().simple());
        self.call(&id, action, Duration::from_secs(30))
    }

    pub fn execute_pending(&self, operation: &super::store::PendingOperation) -> Result<Value> {
        match self.execute_pending_outcome(operation)? {
            OperationOutcome::Complete(value) => Ok(value),
            OperationOutcome::Rejected | OperationOutcome::Interrupted => {
                Err(Error::WorkloadDaemon)
            }
        }
    }

    pub fn execute_pending_outcome(
        &self,
        operation: &super::store::PendingOperation,
    ) -> Result<OperationOutcome> {
        if operation.daemon != "artifactd" {
            return Err(Error::WorkloadState);
        }
        let mut request = operation.request.clone();
        request["operation_id"] = Value::String(operation.operation_id.clone());
        let response = self.exchange_response(request, Duration::from_secs(600))?;
        classify_response(response)
    }

    fn call(&self, operation_id: &str, action: Value, timeout: Duration) -> Result<Value> {
        let request = json!({"version":VERSION,"operation_id":operation_id,"action":action});
        let response = self.exchange_response(request, timeout)?;
        match classify_response(response)? {
            OperationOutcome::Complete(value) => Ok(value),
            OperationOutcome::Rejected | OperationOutcome::Interrupted => {
                Err(Error::WorkloadDaemon)
            }
        }
    }

    fn exchange_response(&self, request: Value, timeout: Duration) -> Result<Value> {
        #[cfg(target_os = "linux")]
        {
            return self.exchange_linux(request, timeout);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (request, timeout);
            Err(Error::Configuration)
        }
    }

    #[cfg(target_os = "linux")]
    fn exchange_linux(&self, request: Value, timeout: Duration) -> Result<Value> {
        if request.get("version").and_then(Value::as_u64) != Some(VERSION.into())
            || request
                .get("operation_id")
                .and_then(Value::as_str)
                .is_none()
            || request
                .pointer("/action/operation")
                .and_then(Value::as_str)
                .is_none()
        {
            return Err(Error::WorkloadDaemon);
        }
        let bytes = serde_json::to_vec(&request).map_err(|_| Error::WorkloadDaemon)?;
        if bytes.is_empty() || bytes.len() > MAX_PACKET {
            return Err(Error::WorkloadDaemon);
        }
        let socket = net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|_| Error::Transport)?;
        match net::connect(
            &socket,
            &SocketAddrUnix::new(&self.path).map_err(|_| Error::Configuration)?,
        ) {
            Ok(()) => (),
            Err(error) if error == Errno::INPROGRESS => {
                wait(&socket, PollFlags::OUT, Duration::from_secs(30))?;
                net::sockopt::socket_error(&socket)
                    .map_err(|_| Error::Transport)?
                    .map_err(|_| Error::Transport)?;
            }
            Err(_) => return Err(Error::Transport),
        }
        if net::sockopt::socket_peercred(&socket)
            .map_err(|_| Error::Transport)?
            .uid
            .as_raw()
            != self.server_uid
        {
            return Err(Error::WorkloadDaemon);
        }
        wait(&socket, PollFlags::OUT, Duration::from_secs(30))?;
        send_packet(&socket, &bytes)?;
        wait(&socket, PollFlags::IN, timeout)?;
        let bytes = receive_packet(&socket)?;
        let response: Value = serde_json::from_slice(&bytes).map_err(|_| Error::WorkloadDaemon)?;
        if response.get("version").and_then(Value::as_u64) != Some(VERSION.into())
            || response.get("operation_id") != request.get("operation_id")
        {
            return Err(Error::WorkloadDaemon);
        }
        Ok(response)
    }
}

fn classify_response(response: Value) -> Result<OperationOutcome> {
    match response.get("result").and_then(Value::as_object) {
        Some(result) if result.len() == 1 => {
            if let Some(value) = result.get("Ok") {
                return Ok(OperationOutcome::Complete(value.clone()));
            }
            if let Some(message) = result.get("Err").and_then(Value::as_str) {
                return Ok(if message == INTERRUPTED_RESULT {
                    OperationOutcome::Interrupted
                } else {
                    OperationOutcome::Rejected
                });
            }
            Err(Error::WorkloadDaemon)
        }
        _ => Err(Error::WorkloadDaemon),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_journal_replay_results_are_classified_without_losing_uncertainty() {
        assert!(matches!(
            classify_response(json!({"result":{"Ok":{"pin_id":"pin-1"}}})),
            Ok(OperationOutcome::Complete(_))
        ));
        assert!(matches!(
            classify_response(json!({"result":{"Err":"invalid digest"}})),
            Ok(OperationOutcome::Rejected)
        ));
        assert!(matches!(
            classify_response(json!({"result":{"Err":INTERRUPTED_RESULT}})),
            Ok(OperationOutcome::Interrupted)
        ));
        assert!(classify_response(json!({"result":{"Ok":{},"Err":"bad"}})).is_err());
        assert!(classify_response(json!({"result":"bad"})).is_err());
    }
}

#[cfg(target_os = "linux")]
fn wait(socket: impl AsFd, flags: PollFlags, timeout: Duration) -> Result<()> {
    let mut fds = [PollFd::new(&socket, flags)];
    let timespec = Timespec {
        tv_sec: timeout.as_secs().min(i64::MAX as u64) as i64,
        tv_nsec: timeout.subsec_nanos() as i64,
    };
    let ready = poll(&mut fds, Some(&timespec)).map_err(|_| Error::Transport)?;
    let events = fds[0].revents();
    if ready == 1
        && events.contains(flags)
        && !events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
    {
        Ok(())
    } else {
        Err(Error::Transport)
    }
}

#[cfg(target_os = "linux")]
fn send_packet(socket: impl AsFd, bytes: &[u8]) -> Result<()> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let sent = net::sendmsg(
        socket,
        &[IoSlice::new(bytes)],
        &mut ancillary,
        SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
    )
    .map_err(|_| Error::Transport)?;
    if sent == bytes.len() {
        Ok(())
    } else {
        Err(Error::Transport)
    }
}

#[cfg(target_os = "linux")]
fn receive_packet(socket: impl AsFd) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; MAX_PACKET];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = net::recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT,
    )
    .map_err(|_| Error::Transport)?;
    let mut invalid = message.bytes == 0
        || message
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC);
    for item in ancillary.drain() {
        match item {
            RecvAncillaryMessage::ScmRights(fds) => {
                invalid = true;
                drop(fds);
            }
            _ => invalid = true,
        }
    }
    if invalid {
        return Err(Error::WorkloadDaemon);
    }
    bytes.truncate(message.bytes);
    Ok(bytes)
}
