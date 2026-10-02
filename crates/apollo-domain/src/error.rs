use thiserror::Error;

/// A rejected pure product fact or state transition.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DomainError {
    /// An externally supplied product identifier does not satisfy its frozen bound.
    #[error("invalid {kind}")]
    InvalidIdentifier { kind: &'static str },
    /// A value cannot represent a valid product fact.
    #[error("{aggregate} invariant violated: {rule}")]
    Invariant {
        aggregate: &'static str,
        rule: &'static str,
    },
    /// A state transition is not legal from the aggregate's current state.
    #[error("{aggregate} cannot transition from {from} to {to}")]
    Transition {
        aggregate: &'static str,
        from: &'static str,
        to: &'static str,
    },
    /// A fact belongs to an older authority, revision, or generation.
    #[error("stale {aggregate} fact")]
    Stale { aggregate: &'static str },
}

impl DomainError {
    #[must_use]
    pub const fn invariant(aggregate: &'static str, rule: &'static str) -> Self {
        Self::Invariant { aggregate, rule }
    }
}
