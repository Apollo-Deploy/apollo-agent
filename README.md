# apollo-agent

A lightweight, provider-neutral Linux node telemetry agent for Apollo Cloud,
BYOC and self-hosted control planes. MIT licensed.

**Status: partial production qualification.** This release collects and forwards
telemetry. The opt-in workload path is being qualified; when its `workload` config
is omitted, Apollo Node V2 remains the lifecycle executor. Runtime-generated
mapping, pre-start raw MicroSandbox/build log capture and the complete real-workload
failure gate remain unfinished. Publishing the source does not close those gates.

## Responsibilities

- Authenticate signed, revision-fenced workload assignments over TLS/NKey NATS.
- Sample cgroup v2 CPU, memory, I/O, PIDs and PSI, plus known interface counters.
- Keep bounded metric state and a separate durable critical-event journal.
- Forward opaque log batches from [apollo-logd](https://github.com/Apollo-Deploy/apollo-logd).
- Return local cumulative log ACKs only after authenticated remote durable ACKs.
- When explicitly enabled, accept separately signed workload authority and reconcile
  one networkless, secretless sandbox through artifactd and sandboxd.

```text
Control-plane signed assignments → Agent ← cgroup v2 / interface counters
                                    ↑
Runtime output → logd → bounded WAL → local authenticated IPC
                                    ↓
                         TLS/NKey NATS → telemetry ingest
```

## Build

Rust 1.88.0 and Linux are required for operation. Protobuf generation uses the
checked-in schema and a pinned vendored protoc dependency.

```sh
cargo build --release --locked --bin apollo-agent
cargo fmt --all -- --check
cargo clippy --locked --workspace --lib --bins --examples -- -D warnings
cargo run --locked --release --example peer_qualification
```

The last command verifies Linux peer-credential rejection through an isolated
local socket. CI uses these commands; ordinary Rust unit tests are not run.

## Configuration

See [`deploy/config.example.json`](deploy/config.example.json) and the hardened
[`systemd unit`](deploy/apollo-agent.service). Provision a dedicated `apollo-logd`
account, protected directories and credentials through your authorized installer.
The config template's UID/GID values are deliberately unset. Render them with:

```sh
python3 deploy/configure-logd-peer.py deploy/config.example.json /etc/apollo-agent/config.json
```

The config directory must already exist with mode 0700 and appropriate ownership.
The renderer creates a mode-0600 file and refuses to overwrite an existing file.
Use `apollo-agent run /etc/apollo-agent/config.json` after filling in the authorized
enrollment, trust roots, credentials and runtime mapping.

`assignment_source: "control_plane"` requests live signed telemetry authority; `"file"`
is available for controlled telemetry qualification. The mapping manifest remains a current
integration gap: it must come from a trusted runtime adapter, match boot ID and
assignment revision, and bind workload, generation, desired digest, relative
cgroup path and interface index exactly. This release is not a standalone installer.

Workload orchestration is disabled by default. To enable it, replace `"workload": null`
with the block below and provision daemon socket owners and the compatible workload
authority/observation subjects. Authority uses `apollo.node.workload.authority.<node>.<credential-generation>`;
observations use `apollo.node.workload.observations.<node>.<credential-generation>`. The
control-plane issuer and NATS ACLs must implement the `apollo.workload.v1` protobuf
contract. Workload authority is stored separately from telemetry assignments. Phase 1
rejects ports, environment values, and secret references, uses `network: none`, and
starts the OCI image's baked entrypoint unless a signed argv is supplied.

```json
{
  "artifactd_socket": "/run/apollo-artifactd/artifactd.sock",
  "artifactd_server_uid": 991,
  "sandboxd_socket": "/run/apollo-sandboxd/sandboxd.sock",
  "sandboxd_server_uid": 0,
  "sandboxd_artifact_uid": 0,
  "sandboxd_artifact_gid": 0,
  "kernel_profile": "linux-kernel-v1",
  "runtime_profile": "firecracker-v1",
  "reconcile_interval_ms": 5000,
  "lease_seconds": 3600
}
```

The config alone does not qualify runtime execution: artifactd must authorize the
Agent producer and sandboxd consumer, sandboxd must expose verified runtime catalogs,
and Linux/KVM recovery tests must pass. Agent state is checksummed, versioned, bounded,
and fsync-backed. A sandbox mutation with an indeterminate receipt is held for daemon
inspection; Agent does not infer failure from a timeout.

Endpoints and trust roots are configurable. The control-plane issuer, compatible
NATS permissions and durable ingest service are external prerequisites, not
included in this repository. No cloud SDK or SaaS endpoint is hardcoded.

## Security and compatibility

Remote protobuf protocol major 1 and local ALP1/ALR1 version 1 are retained.
Node identity alone does not authorize arbitrary telemetry: ingest must verify
current workload/generation/stream assignments independently. Do not grant
workloads access to host credentials or the local socket.

See [security](SECURITY.md), [source provenance](docs/source-export.md), and
[MIT license](LICENSE). Shared protocol sources are vendored for reproducible,
independent builds. This repository does not publish packages to crates.io.
