use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use seren_secrets_crypto::keys::{
    IdentityKemKeypair, IdentityKemPrivateKey, IdentitySigningKeypair, IdentitySigningPrivateKey,
};
use seren_secrets_resolver::seren_secrets::{SerenSecretsResolver, SerenSecretsResolverConfig};
use seren_secrets_resolver::{AgentSecretResolver, ResolutionContext};
use subtle::ConstantTimeEq;
use tower::limit::GlobalConcurrencyLimitLayer;
use tracing::info;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Minimum sidecar bearer-token length.
const MIN_SIDECAR_TOKEN_LEN: usize = 32;

/// Maximum concurrent upstream resolve calls.
const MAX_CONCURRENT_RESOLVES: usize = 64;

#[derive(Clone)]
struct AppState {
    sidecar_token: Zeroizing<String>,
    deployments: Arc<HashMap<Uuid, DeploymentEntry>>,
}

/// Wire shape of an identity entry in `SEREN_SECRETS_IDENTITIES_JSON`.
/// Held only long enough to decode the private key material at startup;
/// the base64 strings are dropped after `into_deployment_entry` returns.
#[derive(Deserialize)]
struct IdentityConfig {
    deployment_id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
    identity_id: Uuid,
    signing_private_key_b64: String,
    kem_private_key_b64: String,
}

impl std::fmt::Debug for IdentityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityConfig")
            .field("deployment_id", &self.deployment_id)
            .field("organization_id", &self.organization_id)
            .field("user_id", &self.user_id)
            .field("identity_id", &self.identity_id)
            .field("signing_private_key_b64", &"<redacted>")
            .field("kem_private_key_b64", &"<redacted>")
            .finish()
    }
}

/// Resolver plus identity bindings for one deployment.
struct DeploymentEntry {
    organization_id: Uuid,
    user_id: Uuid,
    identity_id: Uuid,
    resolver: Arc<SerenSecretsResolver>,
}

fn load_deployments(
    identities_json: &str,
    secrets_base_url: &str,
    secrets_bearer_token: &str,
) -> anyhow::Result<HashMap<Uuid, DeploymentEntry>> {
    let configs: Vec<IdentityConfig> = serde_json::from_str(identities_json)?;
    let mut deployments = HashMap::with_capacity(configs.len());
    for config in configs {
        let IdentityConfig {
            deployment_id,
            organization_id,
            user_id,
            identity_id,
            signing_private_key_b64,
            kem_private_key_b64,
        } = config;
        let signing_private_key_b64 = Zeroizing::new(signing_private_key_b64);
        let kem_private_key_b64 = Zeroizing::new(kem_private_key_b64);
        let signing_bytes = Zeroizing::new(
            B64.decode(signing_private_key_b64.as_bytes())
                .map_err(|err| {
                    anyhow::anyhow!(
                        "identity {identity_id}: signing_private_key_b64 must be base64: {err}"
                    )
                })?,
        );
        let kem_bytes =
            Zeroizing::new(B64.decode(kem_private_key_b64.as_bytes()).map_err(|err| {
                anyhow::anyhow!("identity {identity_id}: kem_private_key_b64 must be base64: {err}")
            })?);
        let signing_private = IdentitySigningPrivateKey::from_slice(&signing_bytes)
            .map_err(|_| {
                anyhow::anyhow!(
                    "identity {identity_id}: signing_private_key_b64 is not a valid Ed25519 private key"
                )
            })?;
        let kem_private = IdentityKemPrivateKey::from_slice(&kem_bytes).map_err(|_| {
            anyhow::anyhow!(
                "identity {identity_id}: kem_private_key_b64 is not a valid X25519 private key"
            )
        })?;
        let resolver = SerenSecretsResolver::new(SerenSecretsResolverConfig {
            base_url: secrets_base_url.to_string(),
            bearer_token: secrets_bearer_token.to_string(),
            caller_identity_id: identity_id,
            signing_keypair: IdentitySigningKeypair::from_private(signing_private),
            kem_keypair: IdentityKemKeypair::from_private(kem_private),
        })
        .map_err(|err| {
            anyhow::anyhow!("identity {identity_id}: failed to build resolver: {err}")
        })?;
        deployments.insert(
            deployment_id,
            DeploymentEntry {
                organization_id,
                user_id,
                identity_id,
                resolver: Arc::new(resolver),
            },
        );
    }
    Ok(deployments)
}

#[derive(Debug, Deserialize)]
struct SidecarResolveRequest {
    uri: String,
    deployment_id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
    correlation_id: Option<Uuid>,
}

// No `Debug`: this response holds plaintext.
#[derive(Serialize)]
struct SidecarResolveResponse {
    #[serde(serialize_with = "serialize_zeroizing_string")]
    plaintext: Zeroizing<String>,
    field_name: String,
    source: &'static str,
}

fn serialize_zeroizing_string<S>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.as_str())
}

/// Keeps response bytes zeroizing until hyper finishes writing them.
struct ZeroizingJsonOwner(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for ZeroizingJsonOwner {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Serialize `value` into a `Zeroizing<Vec<u8>>` sized for the
/// expected output, then build a JSON response whose body keeps the
/// zeroizing buffer alive until the response is fully written. The
/// capacity hint exists to avoid mid-serialization reallocations:
/// each realloc copies the partially-written plaintext into a new
/// buffer and frees the old allocation without zeroing it.
fn zeroizing_json_response<T: Serialize>(value: &T, capacity_hint: usize) -> Response {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(capacity_hint));
    if let Err(err) = serde_json::to_writer(&mut *buf, value) {
        tracing::error!(error = %err, "sidecar JSON serialization failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "serialization error".to_string(),
                approval_request_id: None,
            }),
        )
            .into_response();
    }
    let body = Body::from(Bytes::from_owner(ZeroizingJsonOwner(buf)));
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .expect("static header value and known status")
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    /// Populated only when approval policy makes the denial recoverable.
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_request_id: Option<Uuid>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let bind = sidecar_bind_from_env()?;
    let sidecar_token = required_env("SEREN_SECRETS_SIDECAR_TOKEN")?;
    validate_sidecar_token(&sidecar_token)?;
    let secrets_base_url = required_env("SEREN_SECRETS_BASE_URL")?;
    let secrets_bearer_token = required_env("SEREN_SECRETS_BEARER_TOKEN")?;
    let identities_json = required_env("SEREN_SECRETS_IDENTITIES_JSON")?;
    let deployments = load_deployments(&identities_json, &secrets_base_url, &secrets_bearer_token)?;
    info!(deployments = deployments.len(), "loaded agent identities");

    let state = AppState {
        sidecar_token: Zeroizing::new(sidecar_token),
        deployments: Arc::new(deployments),
    };
    // Axum layers are inside-out; guard must run before body/concurrency work.
    let app = Router::new()
        .route("/resolve", post(resolve))
        .layer(GlobalConcurrencyLimitLayer::new(MAX_CONCURRENT_RESOLVES))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(from_fn_with_state(state.clone(), guard))
        .with_state(state);

    info!(%bind, "starting seren-secrets sidecar");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Outermost local-origin and bearer-token guard.
async fn guard(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    if !local_request_ok(request.headers()) {
        return Err(err(StatusCode::FORBIDDEN, "request must originate locally"));
    }
    authorize(&state, request.headers())?;
    Ok(next.run(request).await)
}

async fn resolve(
    State(state): State<AppState>,
    Json(body): Json<SidecarResolveRequest>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let deployment = state
        .deployments
        .get(&body.deployment_id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "deployment identity not configured"))?;
    if deployment.organization_id != body.organization_id || deployment.user_id != body.user_id {
        return Err(err(StatusCode::FORBIDDEN, "deployment identity mismatch"));
    }

    let mut ctx =
        ResolutionContext::for_agent(deployment.identity_id, body.organization_id, body.user_id);
    if let Some(correlation_id) = body.correlation_id {
        ctx = ctx.with_correlation_id(correlation_id);
    }

    let secret = deployment
        .resolver
        .resolve(&body.uri, &ctx)
        .await
        .map_err(map_resolver_error)?;
    // 4x plaintext absorbs worst-case JSON escaping (control bytes
    // expand to \uXXXX, six bytes); the constant covers the JSON
    // envelope ("plaintext":"","field_name":"","source":"seren-secrets").
    let capacity_hint = secret.plaintext.len() * 4 + secret.field_name.len() + 128;
    let response = SidecarResolveResponse {
        plaintext: secret.plaintext,
        field_name: secret.field_name,
        source: "seren-secrets",
    };
    Ok(zeroizing_json_response(&response, capacity_hint))
}

fn authorize(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err(err(StatusCode::UNAUTHORIZED, "missing authorization"));
    };
    let Ok(value) = value.to_str() else {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid authorization"));
    };
    let value = value.as_bytes();
    let expected_prefix = b"Bearer ";
    let expected_len = expected_prefix.len() + state.sidecar_token.len();
    if value.len() == expected_len
        && &value[..expected_prefix.len()] == expected_prefix
        && value[expected_prefix.len()..]
            .ct_eq(state.sidecar_token.as_bytes())
            .into()
    {
        Ok(())
    } else {
        Err(err(StatusCode::UNAUTHORIZED, "invalid authorization"))
    }
}

/// Local IPC only: loopback Host and no Origin.
fn local_request_ok(headers: &HeaderMap) -> bool {
    if headers.contains_key(axum::http::header::ORIGIN) {
        return false;
    }
    match headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
    {
        Some(host) => host_is_loopback(host),
        None => false,
    }
}

/// Accepts optional port and bracketed IPv6 (`[::1]:8787`).
fn host_is_loopback(host: &str) -> bool {
    let hostname = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((inner, _)) => inner,
            None => return false,
        }
    } else {
        host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
    };
    if hostname.eq_ignore_ascii_case("localhost") {
        return true;
    }
    hostname
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

fn map_resolver_error(
    error: seren_secrets_resolver::ResolverError,
) -> (StatusCode, Json<ErrorResponse>) {
    match error {
        seren_secrets_resolver::ResolverError::InvalidUri(_)
        | seren_secrets_resolver::ResolverError::InvalidInput(_)
        | seren_secrets_resolver::ResolverError::Malformed(_)
        | seren_secrets_resolver::ResolverError::Crypto(_) => {
            err(StatusCode::BAD_REQUEST, "bad secret reference")
        }
        seren_secrets_resolver::ResolverError::ApprovalRequired { request_id } => {
            approval_err(request_id)
        }
        seren_secrets_resolver::ResolverError::ServerError { status, .. } => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            err(status, "upstream secrets service rejected secret reference")
        }
        seren_secrets_resolver::ResolverError::Transport(_) => err(
            StatusCode::BAD_GATEWAY,
            "upstream secrets service unavailable",
        ),
        seren_secrets_resolver::ResolverError::UnsupportedScheme(_)
        | seren_secrets_resolver::ResolverError::NotImplemented(_)
        | seren_secrets_resolver::ResolverError::UnknownField(_) => {
            err(StatusCode::BAD_REQUEST, "unsupported secret reference")
        }
        seren_secrets_resolver::ResolverError::ResponseMismatch => err(
            StatusCode::BAD_GATEWAY,
            "upstream secrets service returned a mismatched record",
        ),
    }
}

fn err(status: StatusCode, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: message.to_string(),
            approval_request_id: None,
        }),
    )
}

fn approval_err(request_id: Uuid) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: "approval required".to_string(),
            approval_request_id: Some(request_id),
        }),
    )
}

fn required_env(name: &str) -> anyhow::Result<String> {
    let value = env::var(name)?;
    if value.trim().is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    Ok(value)
}

fn validate_sidecar_token(token: &str) -> anyhow::Result<()> {
    if token.len() < MIN_SIDECAR_TOKEN_LEN {
        anyhow::bail!("SEREN_SECRETS_SIDECAR_TOKEN must be at least {MIN_SIDECAR_TOKEN_LEN} bytes");
    }
    Ok(())
}

fn sidecar_bind_from_env() -> anyhow::Result<SocketAddr> {
    let bind: SocketAddr = env::var("SEREN_SECRETS_SIDECAR_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse()?;
    validate_sidecar_bind(bind, bool_env("SEREN_SECRETS_SIDECAR_ALLOW_REMOTE_BIND")?)?;
    Ok(bind)
}

fn bool_env(name: &str) -> anyhow::Result<bool> {
    let value = match env::var(name) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => Ok(false),
        "1" | "true" | "yes" | "on" => Ok(true),
        _ => anyhow::bail!("{name} must be a boolean"),
    }
}

fn validate_sidecar_bind(bind: SocketAddr, allow_remote_bind: bool) -> anyhow::Result<()> {
    if allow_remote_bind || bind.ip().is_loopback() {
        return Ok(());
    }
    anyhow::bail!(
        "SEREN_SECRETS_SIDECAR_BIND must be loopback unless SEREN_SECRETS_SIDECAR_ALLOW_REMOTE_BIND=true"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_loopback_sidecar_bind() {
        validate_sidecar_bind("127.0.0.1:8787".parse().unwrap(), false).unwrap();
        validate_sidecar_bind("[::1]:8787".parse().unwrap(), false).unwrap();
    }

    #[test]
    fn rejects_remote_sidecar_bind_by_default() {
        let err = validate_sidecar_bind("0.0.0.0:8787".parse().unwrap(), false).unwrap_err();
        assert!(err.to_string().contains("must be loopback"));
    }

    #[test]
    fn accepts_remote_sidecar_bind_with_explicit_opt_in() {
        validate_sidecar_bind("0.0.0.0:8787".parse().unwrap(), true).unwrap();
    }

    #[test]
    fn rejects_short_sidecar_token() {
        assert!(validate_sidecar_token("short").is_err());
        validate_sidecar_token(&"x".repeat(MIN_SIDECAR_TOKEN_LEN)).unwrap();
    }

    #[test]
    fn host_is_loopback_accepts_loopback_targets() {
        assert!(host_is_loopback("127.0.0.1:8787"));
        assert!(host_is_loopback("127.0.0.1"));
        assert!(host_is_loopback("localhost:8787"));
        assert!(host_is_loopback("localhost"));
        assert!(host_is_loopback("[::1]:8787"));
        assert!(host_is_loopback("[::1]"));
    }

    #[test]
    fn host_is_loopback_rejects_remote_and_rebinding_targets() {
        assert!(!host_is_loopback("evil.com:8787"));
        assert!(!host_is_loopback("remote.example"));
        assert!(!host_is_loopback("8.8.8.8:8787"));
        assert!(!host_is_loopback("[2001:4860:4860::8888]:8787"));
    }

    #[test]
    fn local_request_ok_requires_loopback_host_and_no_origin() {
        use axum::http::header::{HOST, ORIGIN};

        let mut headers = HeaderMap::new();
        headers.insert(HOST, "127.0.0.1:8787".parse().unwrap());
        assert!(local_request_ok(&headers));

        let mut with_origin = headers.clone();
        with_origin.insert(ORIGIN, "http://evil.example".parse().unwrap());
        assert!(!local_request_ok(&with_origin));

        let mut rebind = HeaderMap::new();
        rebind.insert(HOST, "evil.example:8787".parse().unwrap());
        assert!(!local_request_ok(&rebind));

        assert!(!local_request_ok(&HeaderMap::new()));
    }

    #[test]
    fn maps_approval_required_to_403_with_request_id() {
        // Keep approval-required distinguishable from a generic 403.
        let request_id = Uuid::new_v4();
        let (status, payload) =
            map_resolver_error(seren_secrets_resolver::ResolverError::ApprovalRequired {
                request_id,
            });
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(payload.0.approval_request_id, Some(request_id));
        assert_eq!(payload.0.error, "approval required");
    }

    #[test]
    fn maps_non_approval_errors_without_request_id() {
        let (status, payload) = map_resolver_error(
            seren_secrets_resolver::ResolverError::InvalidUri("missing field"),
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(payload.0.approval_request_id.is_none());

        let (status, payload) =
            map_resolver_error(seren_secrets_resolver::ResolverError::ResponseMismatch);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(payload.0.approval_request_id.is_none());
    }

    #[tokio::test]
    async fn zeroizing_json_response_round_trips() {
        let response_value = SidecarResolveResponse {
            plaintext: Zeroizing::new("hunter2".to_string()),
            field_name: "password".to_string(),
            source: "seren-secrets",
        };
        let response = zeroizing_json_response(&response_value, 256);
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .expect("content-type header set");
        assert_eq!(content_type, "application/json");
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("body collects");
        let decoded: serde_json::Value =
            serde_json::from_slice(&bytes).expect("body is valid json");
        assert_eq!(decoded["plaintext"], "hunter2");
        assert_eq!(decoded["field_name"], "password");
        assert_eq!(decoded["source"], "seren-secrets");
    }

    #[test]
    fn identity_config_debug_redacts_private_keys() {
        let cfg = IdentityConfig {
            deployment_id: Uuid::nil(),
            organization_id: Uuid::nil(),
            user_id: Uuid::nil(),
            identity_id: Uuid::nil(),
            signing_private_key_b64: "SIGN-SECRET-KEY-MATERIAL".into(),
            kem_private_key_b64: "KEM-SECRET-KEY-MATERIAL".into(),
        };
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("SIGN-SECRET-KEY-MATERIAL"),
            "Debug leaked signing key: {rendered}"
        );
        assert!(
            !rendered.contains("KEM-SECRET-KEY-MATERIAL"),
            "Debug leaked kem key: {rendered}"
        );
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn load_deployments_rejects_invalid_signing_key() {
        let identities = serde_json::json!([{
            "deployment_id": Uuid::new_v4(),
            "organization_id": Uuid::new_v4(),
            "user_id": Uuid::new_v4(),
            "identity_id": Uuid::new_v4(),
            "signing_private_key_b64": "!!!not-base64",
            "kem_private_key_b64": B64.encode([0u8; 32]),
        }])
        .to_string();
        let err = match load_deployments(&identities, "https://example", "tok") {
            Ok(_) => panic!("invalid signing key must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("signing_private_key_b64"),
            "diag should name the bad field: {err}"
        );
    }
}
