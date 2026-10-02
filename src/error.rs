#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("agent configuration rejected")]
    Configuration,
    #[error("agent credentials or assignments require reload")]
    Reload,
    #[error("agent identity rejected")]
    Identity,
    #[error("runtime mapping rejected")]
    Mapping,
    #[error("kernel counters unavailable or invalid")]
    Counters,
    #[error("telemetry transport unavailable")]
    Transport,
    #[error("bounded event journal is full")]
    JournalFull,
    #[error("telemetry protocol rejected")]
    Protocol(#[from] apollo_node_telemetry_protocol::ProtocolError),
    #[error("local storage operation failed")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
