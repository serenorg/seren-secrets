use std::fmt;

use thiserror::Error;

/// Stable classification for failures in the resolver's upstream transport.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportErrorKind {
    /// The connection or response exceeded a configured timeout.
    Timeout,
    /// A connection to the upstream endpoint could not be established.
    Connect,
    /// Another client, request, redirect, or response-stream failure occurred.
    Other,
}

/// An opaque upstream transport failure.
///
/// Use [`TransportError::kind`] for stable classification. The concrete client
/// error remains available through [`std::error::Error::source`] without being
/// part of this crate's public fields or constructors.
pub struct TransportError {
    kind: TransportErrorKind,
    source: reqwest::Error,
}

impl TransportError {
    fn from_reqwest(source: reqwest::Error) -> Self {
        let kind = if source.is_timeout() {
            TransportErrorKind::Timeout
        } else if source.is_connect() {
            TransportErrorKind::Connect
        } else {
            TransportErrorKind::Other
        };
        Self { kind, source }
    }

    /// Return a client-independent classification of the failure.
    pub fn kind(&self) -> TransportErrorKind {
        self.kind
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            TransportErrorKind::Timeout => f.write_str("upstream request timed out"),
            TransportErrorKind::Connect => f.write_str("upstream connection failed"),
            TransportErrorKind::Other => f.write_str("upstream transport failed"),
        }
    }
}

impl fmt::Debug for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportError")
            .field("kind", &self.kind)
            .field("source", &"<redacted>")
            .finish()
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

// `ServerError.body` may contain sensitive untrusted input, so `Debug` is
// implemented below without exposing it.
#[derive(Error)]
pub enum ResolverError {
    #[error("uri scheme not handled by any registered resolver: {0}")]
    UnsupportedScheme(String),

    #[error("uri shape is invalid: {0}")]
    InvalidUri(&'static str),

    #[error(transparent)]
    Transport(#[from] TransportError),

    #[error("server returned status {status}")]
    ServerError {
        status: u16,
        /// Server-supplied response body, retained for structured inspection.
        /// It is omitted from `Display` and `Debug` and must not be logged.
        body: String,
    },

    #[error("response body malformed: {0}")]
    Malformed(&'static str),

    #[error("crypto error: {0}")]
    Crypto(#[from] seren_secrets_crypto::CryptoError),

    #[error("approval required (request_id={request_id})")]
    ApprovalRequired { request_id: uuid::Uuid },

    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),

    #[error("requested field not found on item: {0}")]
    UnknownField(String),

    #[error("server returned a record that does not match the requested vault/item")]
    ResponseMismatch,

    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
}

impl fmt::Debug for ResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedScheme(s) => f.debug_tuple("UnsupportedScheme").field(s).finish(),
            Self::InvalidUri(s) => f.debug_tuple("InvalidUri").field(s).finish(),
            Self::Transport(error) => f.debug_tuple("Transport").field(error).finish(),
            // Preserve the error shape without exposing the untrusted body.
            Self::ServerError { status, body: _ } => f
                .debug_struct("ServerError")
                .field("status", status)
                .field("body", &"<redacted>")
                .finish(),
            Self::Malformed(s) => f.debug_tuple("Malformed").field(s).finish(),
            Self::Crypto(e) => f.debug_tuple("Crypto").field(e).finish(),
            Self::ApprovalRequired { request_id } => f
                .debug_struct("ApprovalRequired")
                .field("request_id", request_id)
                .finish(),
            Self::NotImplemented(s) => f.debug_tuple("NotImplemented").field(s).finish(),
            Self::UnknownField(s) => f.debug_tuple("UnknownField").field(s).finish(),
            Self::ResponseMismatch => f.write_str("ResponseMismatch"),
            Self::InvalidInput(s) => f.debug_tuple("InvalidInput").field(s).finish(),
        }
    }
}

impl ResolverError {
    pub(crate) fn transport(source: reqwest::Error) -> Self {
        Self::Transport(TransportError::from_reqwest(source))
    }
}

/// Extract the approval request id from a server or gateway error body.
///
/// Returns `None` for any other shape so callers fall back to a plain
/// [`ResolverError::ServerError`].
pub(crate) fn approval_request_id_from_value(value: &serde_json::Value) -> Option<uuid::Uuid> {
    approval_request_id_from_error(value).or_else(|| {
        value
            .get("data")
            .and_then(|data| data.get("body"))
            .and_then(approval_request_id_from_error)
    })
}

fn approval_request_id_from_error(value: &serde_json::Value) -> Option<uuid::Uuid> {
    value
        .get("error")
        .and_then(|error| error.get("approval_request_id"))
        .and_then(serde_json::Value::as_str)
        .and_then(|raw| raw.parse().ok())
}

/// Cap a server-supplied error body before storing it in a [`ResolverError`].
///
/// Bound the length on a char boundary before callers can log or persist it.
pub fn truncate_error_body(mut text: String) -> String {
    const MAX_ERROR_BODY: usize = 1024;
    if text.len() > MAX_ERROR_BODY {
        let mut end = MAX_ERROR_BODY;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("... [truncated]");
    }
    text
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::{ResolverError, TransportErrorKind, approval_request_id_from_value};

    #[test]
    fn transport_error_hides_client_details_but_preserves_source() {
        let source = reqwest::Proxy::all("not a valid proxy URL").unwrap_err();
        let error = ResolverError::transport(source);

        let ResolverError::Transport(transport) = &error else {
            panic!("expected transport error");
        };
        assert_eq!(transport.kind(), TransportErrorKind::Other);
        assert!(transport.source().is_some());
        assert!(error.source().is_some());
        assert_eq!(error.to_string(), "upstream transport failed");
        let debugged = format!("{error:?}");
        assert!(debugged.contains("<redacted>"), "{debugged}");
        assert!(!debugged.contains("not a valid proxy URL"), "{debugged}");
    }

    #[test]
    fn server_error_display_omits_upstream_body() {
        let error = ResolverError::ServerError {
            status: 500,
            body: "server-supplied sensitive material".to_string(),
        };

        let displayed = error.to_string();
        assert_eq!(displayed, "server returned status 500");
        assert!(!displayed.contains("sensitive material"));
    }

    #[test]
    fn server_error_debug_omits_upstream_body() {
        let error = ResolverError::ServerError {
            status: 500,
            body: "server-supplied sensitive material".to_string(),
        };

        // Debug must preserve the same redaction invariant as Display.
        let debugged = format!("{error:?}");
        assert!(!debugged.contains("sensitive material"), "{debugged}");
        assert!(debugged.contains("<redacted>"), "{debugged}");
        assert!(debugged.contains("500"), "{debugged}");
    }

    #[test]
    fn parses_approval_request_id_from_envelope() {
        let id = "22222222-2222-2222-2222-222222222222";
        let value = serde_json::json!({
            "error": { "message": "approval required", "code": 403, "approval_request_id": id }
        });
        assert_eq!(
            approval_request_id_from_value(&value),
            Some(id.parse().unwrap())
        );
    }

    #[test]
    fn parses_approval_request_id_from_metered_envelope() {
        let id = "33333333-3333-3333-3333-333333333333";
        let value = serde_json::json!({
            "data": {
                "status": 403,
                "body": {
                    "error": {
                        "message": "approval required",
                        "code": 403,
                        "approval_request_id": id,
                    }
                }
            }
        });
        assert_eq!(
            approval_request_id_from_value(&value),
            Some(id.parse().unwrap())
        );
    }

    #[test]
    fn returns_none_for_non_approval_bodies() {
        assert_eq!(
            approval_request_id_from_value(&serde_json::json!({ "error": { "code": 403 } })),
            None
        );
        assert_eq!(
            approval_request_id_from_value(&serde_json::json!({ "data": { "x": 1 } })),
            None
        );
        // A malformed id does not panic; it is simply absent.
        assert_eq!(
            approval_request_id_from_value(
                &serde_json::json!({ "error": { "approval_request_id": "not-a-uuid" } })
            ),
            None
        );
    }
}
