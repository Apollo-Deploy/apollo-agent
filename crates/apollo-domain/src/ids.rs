//! Opaque, bounded Apollo product identifiers.
//!
//! These values intentionally do not expose `Deref<str>` or unchecked public
//! constructors. That keeps identifier validation at the boundary and prevents
//! accidental substitution of different product identities.

use std::{fmt, str::FromStr};

use crate::DomainError;

macro_rules! identifier {
    ($name:ident, $validator:ident) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Box<str>);

        impl $name {
            /// Parses an externally supplied identifier after applying its product bound.
            pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into();
                if !$validator(&value) {
                    return Err(DomainError::InvalidIdentifier {
                        kind: stringify!($name),
                    });
                }
                Ok(Self(value.into_boxed_str()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = DomainError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }
    };
}

fn is_bounded(value: &str) -> bool {
    !value.trim().is_empty() && value.chars().count() <= 128
}

fn is_principal(value: &str) -> bool {
    !value.trim().is_empty() && value.chars().count() <= 256
}

fn is_workload(value: &str) -> bool {
    value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'_' | b'-' => index > 0,
            _ => false,
        })
        && !value.is_empty()
}

fn is_node(value: &str) -> bool {
    value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'-' => index > 0,
            _ => false,
        })
        && !value.is_empty()
}

fn is_prefixed(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    (16..=64).contains(&suffix.len())
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn is_route(value: &str) -> bool {
    is_prefixed(value, "rte_")
}

fn is_placement(value: &str) -> bool {
    is_prefixed(value, "plc_")
}

fn is_domain(value: &str) -> bool {
    is_prefixed(value, "dom_")
}

fn is_certificate(value: &str) -> bool {
    is_prefixed(value, "crt_")
}

identifier!(PrincipalId, is_principal);
identifier!(OrganizationId, is_bounded);
identifier!(ProjectId, is_bounded);
identifier!(EnvironmentId, is_bounded);
identifier!(ServiceId, is_bounded);
identifier!(SourceSnapshotId, is_bounded);
identifier!(BuildId, is_bounded);
identifier!(ArtifactId, is_bounded);
identifier!(DeploymentId, is_bounded);
identifier!(ReleaseId, is_bounded);
identifier!(WorkloadId, is_workload);
identifier!(PlacementId, is_placement);
identifier!(NodeId, is_node);
identifier!(RegionId, is_bounded);
identifier!(ProviderId, is_bounded);
identifier!(RouteId, is_route);
identifier!(TrafficTargetId, is_bounded);
identifier!(DomainId, is_domain);
identifier!(CertificateId, is_certificate);
identifier!(OperationId, is_bounded);
identifier!(EffectId, is_bounded);

#[cfg(test)]
mod tests {
    use super::{CertificateId, DomainId, NodeId, ProjectId, RouteId, WorkloadId};

    #[test]
    fn identifiers_reject_blank_or_wrongly_scoped_values() {
        assert!(ProjectId::parse(" ").is_err());
        assert!(NodeId::parse("node_with_underscore").is_err());
        assert!(WorkloadId::parse("workload with spaces").is_err());
        assert!(RouteId::parse("route-1").is_err());
        assert!(DomainId::parse("dom_UPPERCASE000000000").is_err());
        assert!(CertificateId::parse("crt_short").is_err());
    }

    #[test]
    fn identifiers_preserve_current_product_forms() {
        assert!(NodeId::parse("node-a-1").is_ok());
        assert!(WorkloadId::parse("workload_a-1").is_ok());
        assert!(RouteId::parse("rte_0123456789abcdef").is_ok());
        assert!(DomainId::parse("dom_0123456789abcdef").is_ok());
        assert!(CertificateId::parse("crt_0123456789abcdef").is_ok());
    }
}
