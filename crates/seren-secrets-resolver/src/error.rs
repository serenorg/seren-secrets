use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("uri scheme not handled by any registered resolver: {0}")]
    UnsupportedScheme(String),

    #[error("uri shape is invalid: {0}")]
    InvalidUri(&'static str),

    #[error("control plane unreachable: {0}")]
    ControlPlaneUnavailable(String),

    #[error("server returned {status}: {body}")]
    ServerError { status: u16, body: String },

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
    use super::approval_request_id_from_value;

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
