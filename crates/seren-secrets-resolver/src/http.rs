//! HTTP hardening helpers.

use std::net::IpAddr;
use std::time::Duration;

use crate::error::ResolverError;
use crate::seren_secrets::ResolverNetwork;

/// Hard caps for buffered server response bodies.
pub(crate) const MAX_RESOLVE_BODY: usize = 16 * 1024 * 1024;
pub(crate) const MAX_GATEWAY_BODY: usize = 64 * 1024 * 1024;
pub(crate) const MAX_ERROR_BODY: usize = 64 * 1024;

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
// Bound the whole request, including body completion, while allowing delayed
// service or gateway responses. Progress does not restart this deadline.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(180);

/// Shared by both network modes and all standalone bootstrap helpers.
/// The internal duration permits short behavioral tests without public policy knobs.
pub(crate) fn client_builder(request_timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(request_timeout)
}

/// Validate `base_url` for `network` and build its HTTP client. The resolver
/// and the vault client both use this, so their transport rules cannot drift.
///
/// `HostEnvironment` requires HTTPS (or HTTP to loopback) and keeps the host's
/// proxy and redirect settings. `Direct` also accepts plain HTTP to another
/// host, because its caller authorizes that transport boundary, but never uses
/// a host proxy or follows a redirect.
pub(crate) fn network_client(
    base_url: &str,
    network: ResolverNetwork,
    request_timeout: Duration,
) -> Result<reqwest::Client, ResolverError> {
    let builder = client_builder(request_timeout);
    let builder = match network {
        ResolverNetwork::HostEnvironment => {
            validate_base_url(base_url)?;
            builder
        }
        ResolverNetwork::Direct => {
            validate_direct_url(base_url)?;
            builder
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
        }
    };
    builder.build().map_err(ResolverError::transport)
}

/// A direct endpoint is HTTP(S) with a host and no credentials, query or fragment.
pub(crate) fn validate_direct_url(base_url: &str) -> Result<(), ResolverError> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|_| ResolverError::InvalidUri("base_url is not a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ResolverError::InvalidUri(
            "base_url must be an HTTP(S) endpoint without credentials, query, or fragment",
        ));
    }
    Ok(())
}

/// Require HTTPS except for loopback development URLs.
pub(crate) fn validate_base_url(base_url: &str) -> Result<(), ResolverError> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|_| ResolverError::InvalidUri("base_url is not a valid URL"))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if url.host_str().is_some_and(is_loopback_host) => Ok(()),
        "http" => Err(ResolverError::InvalidUri(
            "base_url must use https for non-loopback hosts",
        )),
        _ => Err(ResolverError::InvalidUri("base_url scheme must be http(s)")),
    }
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // `Url::host_str` keeps IPv6 brackets.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Append while enforcing the running byte cap.
pub(crate) fn cap_extend(buf: &mut Vec<u8>, chunk: &[u8], cap: usize) -> Result<(), ResolverError> {
    if buf.len().saturating_add(chunk.len()) > cap {
        return Err(ResolverError::Malformed("response body exceeded size cap"));
    }
    buf.extend_from_slice(chunk);
    Ok(())
}

/// Buffer a response body without trusting `Content-Length`.
pub(crate) async fn read_capped(
    mut resp: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, ResolverError> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(ResolverError::transport)? {
        cap_extend(&mut buf, &chunk, cap)?;
    }
    Ok(buf)
}

/// Best-effort capped text for server error bodies.
pub(crate) async fn read_capped_text(resp: reqwest::Response, cap: usize) -> String {
    match read_capped(resp, cap).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_for_any_host() {
        validate_base_url("https://api.example.com").unwrap();
        validate_base_url("https://example.com:8443/base").unwrap();
    }

    #[test]
    fn allows_http_only_for_loopback() {
        validate_base_url("http://localhost:8080").unwrap();
        validate_base_url("http://127.0.0.1:8080").unwrap();
        validate_base_url("http://[::1]:8080").unwrap();
    }

    #[test]
    fn rejects_http_for_remote_host() {
        let err = validate_base_url("http://api.example.com").unwrap_err();
        assert!(matches!(err, ResolverError::InvalidUri(_)));
        // A public IP is not loopback.
        assert!(validate_base_url("http://8.8.8.8").is_err());
    }

    #[test]
    fn rejects_non_http_scheme_and_garbage() {
        assert!(validate_base_url("ftp://example.com").is_err());
        assert!(validate_base_url("not a url").is_err());
        assert!(validate_base_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn cap_extend_rejects_when_total_would_exceed_cap() {
        let mut buf = Vec::new();
        cap_extend(&mut buf, &[0u8; 4], 8).unwrap();
        cap_extend(&mut buf, &[0u8; 4], 8).unwrap();
        assert_eq!(buf.len(), 8);
        let err = cap_extend(&mut buf, &[0u8; 1], 8).unwrap_err();
        assert!(matches!(err, ResolverError::Malformed(_)));
        // The rejected chunk is not appended.
        assert_eq!(buf.len(), 8);
    }
}

#[cfg(test)]
pub(crate) mod test_server;
