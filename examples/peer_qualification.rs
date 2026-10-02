//! Linux peer-credential rejection at the actual local IPC boundary.
#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use apollo_telemetry_protocol::local::{self, Listener, Peer};
    use std::{fs, os::unix::fs::PermissionsExt};
    let root = fs::canonicalize(std::env::temp_dir())?
        .join(format!("apollo-peer-proof-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let outcome = (|| -> Result<(), Box<dyn std::error::Error>> {
        let path = root.join("logd.sock");
        let listener = Listener::bind(&path)?;
        let peer = Peer {
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
        };
        let wrong_uid = Peer {
            uid: peer.uid.wrapping_add(1),
            ..peer
        };
        if local::connect(&path, wrong_uid).is_ok() {
            return Err("mismatched local UID accepted".into());
        }
        let wrong_gid = Peer {
            gid: peer.gid.wrapping_add(1),
            ..peer
        };
        if local::connect(&path, wrong_gid).is_ok() {
            return Err("mismatched SO_PEERCRED GID accepted".into());
        }
        local::wait(&listener.fd, false, 2_000)?;
        let rejected_connection = listener.accept()?;
        peer.authorize(&rejected_connection)?;
        if wrong_uid.authorize(&rejected_connection).is_ok() {
            return Err("accepted connection with unauthorized UID".into());
        }
        let connection = local::connect(&path, peer)?;
        local::wait(&listener.fd, false, 2_000)?;
        let accepted = listener.accept()?;
        peer.authorize(&connection)?;
        peer.authorize(&accepted)?;
        Ok(())
    })();
    fs::remove_dir_all(&root)?;
    outcome?;
    println!(
        "{{\"peer_qualification\":\"PASS\",\"wrong_uid_rejected\":true,\"wrong_gid_rejected\":true,\"accepted_peer_enforced\":true}}"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("SO_PEERCRED qualification requires Linux".into())
}
