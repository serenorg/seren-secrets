#![cfg(feature = "sidecar")]

use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use seren_secrets_crypto::{
    keys::{IdentityKemKeypair, IdentitySigningKeypair},
    protocol::{
        item::{
            ItemContent, LoginContent, encrypt_item_with_content_key, generate_item_content_key,
            wrap_item_content_key,
        },
        resolve::{ResolveRequest, verify_resolve_signature},
        vault::{generate_vault_key, wrap_vault_key_for_identity},
    },
};
use seren_secrets_resolver::{
    AgentSecretResolver, ResolutionContext, ResolverError, ResolverNetwork, SerenSecretsResolver,
    SerenSecretsResolverConfig,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::TcpListener;
use uuid::Uuid;

#[tokio::test]
async fn managed_resolution_ignores_host_proxy_without_changing_host_mode() {
    let calls = Arc::new(AtomicUsize::new(0));
    let proxy_calls = calls.clone();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let proxy = tokio::spawn(async move {
        axum::serve(
            proxy,
            Router::new().fallback(move || async move {
                proxy_calls.fetch_add(1, Ordering::SeqCst);
                (StatusCode::IM_A_TEAPOT, "test proxy was used")
            }),
        )
        .await
        .unwrap();
    });
    for mode in ["managed", "host"] {
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "resolver_network_child", "--nocapture"])
            .env("SEREN_RESOLVER_NETWORK_TEST", mode)
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .kill_on_drop(true);
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            child.env(name, &proxy_url);
        }
        let output = tokio::time::timeout(Duration::from_secs(40), child.output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(mode == "host"));
    }
    proxy.abort();
}

#[tokio::test]
async fn resolver_network_child() {
    let Ok(mode) = std::env::var("SEREN_RESOLVER_NETWORK_TEST") else {
        return;
    };
    let network = match mode.as_str() {
        "managed" => ResolverNetwork::ManagedDirect,
        "host" => ResolverNetwork::HostEnvironment,
        _ => panic!("invalid test mode"),
    };
    let agent_id = Uuid::new_v4();
    let vault_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    let kem = IdentityKemKeypair::generate();
    let signing = IdentitySigningKeypair::generate();
    let verifying_key = signing.public.clone();
    let vault_key = generate_vault_key();
    let content_key = generate_item_content_key();
    let content = ItemContent::Login(LoginContent {
        password: "network-test-value".into(),
        ..Default::default()
    });
    let payload = serde_json::json!({ "data": {
        "vault_id": vault_id, "item_id": item_id, "field_name": "password",
        "content_ciphertext": STANDARD.encode(encrypt_item_with_content_key(&content_key, item_id.as_bytes(), &content).unwrap()),
        "content_key_wrap": STANDARD.encode(wrap_item_content_key(&vault_key, item_id.as_bytes(), &content_key)),
        "wrapped_vault_key": STANDARD.encode(wrap_vault_key_for_identity(&vault_key, &kem.public))
    }});
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", backend.local_addr().unwrap());
    let backend = tokio::spawn(async move {
        axum::serve(
            backend,
            Router::new().route(
                "/resolve",
                post(
                    move |headers: HeaderMap, Json(body): Json<serde_json::Value>| async move {
                        assert_eq!(headers["authorization"], "Bearer synthetic-test-bearer");
                        let signed = ResolveRequest {
                            uri: body["uri"].as_str().unwrap().into(),
                            caller_identity_id: agent_id,
                            issued_at: serde_json::from_value(body["issued_at"].clone()).unwrap(),
                            nonce: serde_json::from_value(body["nonce"].clone()).unwrap(),
                        };
                        verify_resolve_signature(
                            &verifying_key,
                            &signed,
                            &STANDARD
                                .decode(body["request_signature"].as_str().unwrap())
                                .unwrap(),
                        )
                        .unwrap();
                        Json(payload)
                    },
                ),
            ),
        )
        .await
        .unwrap();
    });
    let resolver = SerenSecretsResolver::new(SerenSecretsResolverConfig {
        base_url,
        bearer_token: "synthetic-test-bearer".into(),
        caller_identity_id: agent_id,
        signing_keypair: signing,
        kem_keypair: kem,
        network,
    })
    .unwrap();
    let result = resolver
        .resolve(
            &format!("seren-secrets://{vault_id}/{item_id}/password"),
            &ResolutionContext::for_agent(agent_id, Uuid::new_v4(), Uuid::new_v4()),
        )
        .await;
    match network {
        ResolverNetwork::ManagedDirect => {
            assert_eq!(&*result.unwrap().plaintext, "network-test-value")
        }
        ResolverNetwork::HostEnvironment => assert!(matches!(
            result,
            Err(ResolverError::ServerError { status: 418, .. })
        )),
    }
    backend.abort();
}
