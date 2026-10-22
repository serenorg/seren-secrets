//! Vault client HTTP contract tests. All keys and data are synthetic.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use seren_secrets_crypto::keys::{IdentityKemKeypair, VaultKey};
use seren_secrets_crypto::protocol::{
    attachment,
    item::{
        ItemContent, SecureNoteContent, decrypt_item_with_content_key, decrypt_metadata_json,
        decrypt_title, encrypt_item_with_content_key, encrypt_metadata_json, encrypt_title,
        generate_item_content_key, unwrap_item_content_key, wrap_item_content_key,
    },
    vault::{encrypt_vault_name, generate_vault_key, wrap_vault_key_for_identity},
};
use seren_secrets_resolver::vault::VaultAccessLevel;
use seren_secrets_resolver::vault::{
    AttachmentDeleteOutcome, AttachmentPutOutcome, AttachmentUpload, ItemListState, TrashOutcome,
};
use seren_secrets_resolver::{
    ItemRevision, ResolverError, ResolverNetwork, ServiceTimestamp, VaultClient, VaultClientConfig,
    VaultKeySource,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use zeroize::Zeroizing;

const UPDATED: &str = "2026-10-17T12:34:56.123456Z";
// The same instant as `UPDATED` in another spelling, so a substituted request
// revision or a normalized value cannot pass as the service's own revision.
const DUPLICATE_REVISION: &str = "2026-10-17T08:34:56.1234560-04:00";
const TRASHED: &str = "2026-10-17T12:35:57.654321Z";

#[derive(Clone)]
struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: serde_json::Value,
}

struct FakeServer {
    url: String,
    requests: Arc<Mutex<Vec<Request>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeServer {
    async fn start(
        handler: impl Fn(&Request) -> (u16, serde_json::Value) + Send + 'static,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let header_end = loop {
                    let mut chunk = [0u8; 8192];
                    let n = socket.read(&mut chunk).await.unwrap();
                    assert_ne!(n, 0);
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break index + 4;
                    }
                };
                let header = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                let mut lines = header.lines();
                let mut first = lines.next().unwrap().split_whitespace();
                let method = first.next().unwrap().to_string();
                let path = first.next().unwrap().to_string();
                let headers: BTreeMap<_, _> = lines
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
                    .collect();
                let len = headers
                    .get("content-length")
                    .map(|v| v.parse::<usize>().unwrap())
                    .unwrap_or(0);
                while bytes.len() < header_end + len {
                    let mut chunk = [0u8; 8192];
                    let n = socket.read(&mut chunk).await.unwrap();
                    assert_ne!(n, 0);
                    bytes.extend_from_slice(&chunk[..n]);
                }
                let body = if len == 0 {
                    serde_json::Value::Null
                } else {
                    serde_json::from_slice(&bytes[header_end..header_end + len]).unwrap()
                };
                assert_eq!(
                    headers.get("authorization").map(String::as_str),
                    Some("Bearer synthetic-test-token")
                );
                let req = Request {
                    method,
                    path,
                    headers,
                    body,
                };
                let (status, response) = handler(&req);
                log.lock().unwrap().push(req);
                let body = response.to_string();
                // A redirect names a second path, so following it would be logged.
                let location = if (300..400).contains(&status) {
                    "location: /redirected\r\n"
                } else {
                    ""
                };
                let response = format!(
                    "HTTP/1.1 {status} Test\r\n{location}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    fn client(&self) -> VaultClient {
        VaultClient::new(config(&self.url, ResolverNetwork::HostEnvironment)).unwrap()
    }
}

fn config(base_url: &str, network: ResolverNetwork) -> VaultClientConfig {
    VaultClientConfig {
        base_url: base_url.to_string(),
        bearer_token: "synthetic-test-token".to_string(),
        key_source: VaultKeySource::AgentKey {
            kem_private: IdentityKemKeypair::generate().private,
        },
        network,
        caller_identity_id: Uuid::new_v4(),
    }
}

fn note() -> ItemContent {
    ItemContent::SecureNote(SecureNoteContent::default())
}

fn item_record(key: &VaultKey, vault: Uuid, item: Uuid) -> serde_json::Value {
    item_record_with_metadata(
        key,
        vault,
        item,
        r#"{"item_kind":"secure_note","favorite":true,"reprompt":true,"sensitive":false}"#,
    )
}

fn item_record_with_metadata(
    key: &VaultKey,
    vault: Uuid,
    item: Uuid,
    metadata: &str,
) -> serde_json::Value {
    let content_key = generate_item_content_key();
    let title = encrypt_title(key, item.as_bytes(), "Synthetic fixture title");
    let content = encrypt_item_with_content_key(&content_key, item.as_bytes(), &note()).unwrap();
    serde_json::json!({
        "item_id": item,
        "vault_id": vault,
        "title_ciphertext": B64.encode(title),
        "content_ciphertext": B64.encode(content),
        "content_key_wrap": B64.encode(wrap_item_content_key(key, item.as_bytes(), &content_key)),
        "title_blind_index": "",
        "metadata_ciphertext": B64.encode(encrypt_metadata_json(key, item.as_bytes(), metadata)),
        "sensitive": false,
        "vault_key_version": 1,
        "updated_at": UPDATED,
        "trashed_at": null,
    })
}

fn envelope(status: u16, body: serde_json::Value, metered: bool) -> (u16, serde_json::Value) {
    if metered {
        (
            200,
            serde_json::json!({"data":{"status":status,"body":body}}),
        )
    } else {
        (status, body)
    }
}

#[tokio::test]
async fn conditional_updates_preserve_unconditional_edits_and_map_preconditions() {
    let vault = Uuid::new_v4();
    let item = Uuid::new_v4();
    let key = generate_vault_key();
    let rec = item_record(&key, vault, item);
    let expected_wrap = rec["content_key_wrap"].clone();
    let reply = Arc::new(Mutex::new((200u16, false)));
    let selected = reply.clone();
    let server = FakeServer::start(move |req| {
        assert_eq!(req.path, format!("/vaults/{vault}/items/{item}"));
        if req.method == "GET" {
            return (200, serde_json::json!({"data":rec}));
        }
        assert_eq!(req.method, "PATCH");
        let (status, metered) = *selected.lock().unwrap();
        envelope(
            status,
            if status == 200 {
                serde_json::json!({"data":rec})
            } else {
                serde_json::json!({"error":{"message":"synthetic private upstream error", "approval_request_id":"11111111-1111-1111-1111-111111111111"}})
            },
            metered,
        )
    })
    .await;
    let client = server.client();
    for metered in [false, true] {
        for status in [200, 412, 423, 409, 403] {
            *reply.lock().unwrap() = (status, metered);
            let revision = (status != 200).then(|| UPDATED.parse::<ItemRevision>().unwrap());
            let result = client
                .update_item(
                    vault,
                    item,
                    &key,
                    note(),
                    "Synthetic edited title",
                    &[],
                    None,
                    false,
                    1,
                    revision.as_ref(),
                )
                .await;
            match status {
                200 => assert_eq!(result.unwrap(), UPDATED.parse::<ItemRevision>().unwrap()),
                412 => assert!(matches!(result, Err(ResolverError::Stale))),
                423 => assert!(matches!(result, Err(ResolverError::Rotating))),
                409 => assert!(matches!(result, Err(ResolverError::KeyVersion))),
                403 => assert!(
                    matches!(result, Err(ResolverError::ApprovalRequired { request_id }) if request_id == Uuid::from_bytes([0x11; 16]))
                ),
                _ => unreachable!(),
            }
        }
    }
    let requests = server.requests.lock().unwrap();
    for (i, req) in requests.iter().filter(|r| r.method == "PATCH").enumerate() {
        if i % 5 == 0 {
            assert!(!req.headers.contains_key("if-match"));
        } else {
            assert_eq!(req.headers["if-match"], format!("W/\"{UPDATED}\""));
        }
        assert_eq!(req.body["content_key_wrap"], expected_wrap);
        let content_key = unwrap_item_content_key(
            &key,
            item.as_bytes(),
            &B64.decode(expected_wrap.as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let content = decrypt_item_with_content_key(
            &content_key,
            item.as_bytes(),
            &B64.decode(req.body["content_ciphertext"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(content.into_inner(), note());
        let metadata = decrypt_metadata_json(
            &key,
            item.as_bytes(),
            &B64.decode(req.body["metadata_ciphertext"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&metadata).unwrap();
        assert_eq!(metadata["favorite"], true);
        assert_eq!(metadata["reprompt"], true);
        assert_eq!(req.body["wrapping_key_version"], 1);
    }
    assert!(requests.iter().all(|r| r.method != "DELETE"));
}

#[tokio::test]
async fn item_reads_and_summary_scans_preserve_actual_lifecycle_timestamps() {
    let vault = Uuid::new_v4();
    let item = Uuid::new_v4();
    let key = generate_vault_key();
    let rec = item_record(&key, vault, item);
    let selected = Arc::new(Mutex::new(Some(serde_json::json!(TRASHED))));
    let response_trash = selected.clone();
    let server = FakeServer::start(move |req| {
        assert_eq!(req.method, "GET");
        let mut record = rec.clone();
        if req.path == format!("/vaults/{vault}/items/{item}") {
            record["trashed_at"] = serde_json::json!(TRASHED);
            return (200, serde_json::json!({"data":record}));
        }
        assert!(
            req.path == format!("/vaults/{vault}/items")
                || req.path == format!("/vaults/{vault}/items?state=trashed")
        );
        record.as_object_mut().unwrap().remove("content_ciphertext");
        record.as_object_mut().unwrap().remove("content_key_wrap");
        if req.path.ends_with("?state=trashed") {
            if let Some(value) = response_trash.lock().unwrap().clone() {
                record["trashed_at"] = value;
            } else {
                record.as_object_mut().unwrap().remove("trashed_at");
            }
        }
        (200, serde_json::json!({"data":[record]}))
    })
    .await;
    let client = server.client();
    let read = client.get_item(vault, item, &key).await.unwrap();
    assert_eq!(read.updated_at, UPDATED.parse::<ItemRevision>().unwrap());
    assert_eq!(
        read.trashed_at,
        Some(TRASHED.parse::<ServiceTimestamp>().unwrap())
    );
    assert_eq!(read.content, note());
    for explicit in [false, true] {
        let active = if explicit {
            client
                .list_items_in_state(vault, &key, ItemListState::Active)
                .await
        } else {
            client.list_items(vault, &key).await
        }
        .unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].item_id, item);
        assert_eq!(active[0].title, "Synthetic fixture title");
        assert_eq!(active[0].updated_at, read.updated_at);
        assert_eq!(active[0].trashed_at, None);
    }
    let trashed = client
        .list_items_in_state(vault, &key, ItemListState::Trashed)
        .await
        .unwrap();
    assert_eq!(trashed[0].trashed_at, read.trashed_at);
    assert_eq!(trashed[0].updated_at, read.updated_at);
    for malformed in [
        None,
        Some(serde_json::Value::Null),
        Some(serde_json::json!("synthetic invalid timestamp")),
    ] {
        *selected.lock().unwrap() = malformed;
        let result = client
            .list_items_in_state(vault, &key, ItemListState::Trashed)
            .await;
        assert!(matches!(result, Err(ResolverError::Malformed(_))));
    }
    let requests = server.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.path.ends_with(&item.to_string()))
            .count(),
        1,
        "summaries never hydrate item bodies"
    );
    assert!(requests.iter().all(|r| r.method == "GET"));
}

#[tokio::test]
async fn item_and_attachment_timestamps_keep_the_service_text() {
    let vault = Uuid::new_v4();
    let item = Uuid::new_v4();
    let key = generate_vault_key();
    let rec = item_record(&key, vault, item);
    let request = seren_secrets_resolver::vault::attachments::prepare_upload(
        &key,
        item,
        Uuid::new_v4(),
        upload("synthetic file.bin", b"abc"),
        Some(&ABC_SHA256),
    )
    .unwrap()
    .encrypt();
    let mut row = serde_json::Value::from(request);
    let blob = row.as_object_mut().unwrap().remove("blob").unwrap();
    row["item_id"] = serde_json::json!(item);
    row["size_bytes"] = serde_json::json!(B64.decode(blob.as_str().unwrap()).unwrap().len());
    // The trash and creation times the service sends, and whether its
    // summaries contradict the requested lifecycle state.
    let sent = Arc::new(Mutex::new((
        serde_json::Value::Null,
        serde_json::Value::Null,
        false,
    )));
    let selected = sent.clone();
    let server = FakeServer::start(move |req| {
        assert_eq!(req.method, "GET");
        let (trashed_at, created_at, contradict) = selected.lock().unwrap().clone();
        let item_path = format!("/vaults/{vault}/items/{item}");
        if req.path == format!("{item_path}/attachments") {
            let mut row = row.clone();
            row["created_at"] = created_at;
            return (200, serde_json::json!({"data": [row]}));
        }
        let mut record = rec.clone();
        if req.path == item_path {
            record["trashed_at"] = trashed_at;
            return (200, serde_json::json!({"data": record}));
        }
        let trashed = req.path == format!("/vaults/{vault}/items?state=trashed");
        assert!(trashed || req.path == format!("/vaults/{vault}/items"));
        record.as_object_mut().unwrap().remove("content_ciphertext");
        record.as_object_mut().unwrap().remove("content_key_wrap");
        record["trashed_at"] = if trashed != contradict {
            trashed_at
        } else {
            serde_json::Value::Null
        };
        (200, serde_json::json!({"data": [record]}))
    })
    .await;
    let client = server.client();

    // Spellings a canonical formatter would rewrite: trailing fractional
    // zeros, a numeric offset, and lowercase separators.
    for text in [
        "2026-10-17T12:34:56.250Z",
        "2026-10-17T12:34:56.1234+05:30",
        "2026-10-17t12:34:56.25z",
    ] {
        *sent.lock().unwrap() = (serde_json::json!(text), serde_json::json!(text), false);
        let read = client.get_item(vault, item, &key).await.unwrap();
        let trashed = client
            .list_items_in_state(vault, &key, ItemListState::Trashed)
            .await
            .unwrap();
        let active = client
            .list_items_in_state(vault, &key, ItemListState::Active)
            .await
            .unwrap();
        let listed = client.list_attachments(vault, item, &key).await.unwrap();
        assert_eq!(active[0].trashed_at, None);
        for kept in [
            read.trashed_at.unwrap(),
            trashed[0].trashed_at.clone().unwrap(),
            listed[0].created_at.clone(),
        ] {
            assert_eq!(kept.as_str(), text);
            assert_eq!(kept.to_string(), text);
            assert_eq!(
                serde_json::to_value(&kept).unwrap(),
                serde_json::json!(text)
            );
        }
        // Active and trashed scans still refuse rows contradicting their state.
        sent.lock().unwrap().2 = true;
        for state in [ItemListState::Active, ItemListState::Trashed] {
            assert!(matches!(
                client.list_items_in_state(vault, &key, state).await,
                Err(ResolverError::Malformed("item summary lifecycle"))
            ));
        }
    }

    // Malformed text is still refused with the same errors.
    for malformed in [
        "synthetic invalid timestamp",
        "2026-10-17T12:34:56.250",
        "2026-02-30T12:34:56Z",
    ] {
        let malformed = serde_json::json!(malformed);
        *sent.lock().unwrap() = (malformed.clone(), malformed, false);
        assert!(matches!(
            client.get_item(vault, item, &key).await,
            Err(ResolverError::Malformed("item trashed_at"))
        ));
        assert!(matches!(
            client
                .list_items_in_state(vault, &key, ItemListState::Trashed)
                .await,
            Err(ResolverError::Malformed("item trashed_at"))
        ));
        assert!(matches!(
            client.list_attachments(vault, item, &key).await,
            Err(ResolverError::Malformed("attachment created_at"))
        ));
    }

    // A value of the wrong JSON type fails while decoding the record.
    for wrong in [serde_json::json!(42), serde_json::json!(true)] {
        *sent.lock().unwrap() = (wrong.clone(), wrong, false);
        assert!(matches!(
            client.get_item(vault, item, &key).await,
            Err(ResolverError::Malformed("item record"))
        ));
        assert!(matches!(
            client
                .list_items_in_state(vault, &key, ItemListState::Trashed)
                .await,
            Err(ResolverError::Malformed("item summaries"))
        ));
        assert!(matches!(
            client.list_attachments(vault, item, &key).await,
            Err(ResolverError::Malformed("attachment list"))
        ));
    }
    // A null trash time means not trashed; a null creation time is invalid.
    *sent.lock().unwrap() = (serde_json::Value::Null, serde_json::Value::Null, false);
    let read = client.get_item(vault, item, &key).await.unwrap();
    assert_eq!(read.trashed_at, None);
    assert!(matches!(
        client.list_attachments(vault, item, &key).await,
        Err(ResolverError::Malformed("attachment list"))
    ));
}

#[tokio::test]
async fn trash_only_uses_post_and_preserves_already_trashed_and_stale_outcomes() {
    let vault = Uuid::new_v4();
    let item = Uuid::new_v4();
    let selection = Arc::new(Mutex::new((200, false, "trashed")));
    let response = selection.clone();
    let server = FakeServer::start(move |req| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, format!("/vaults/{vault}/items/{item}/trash"));
        let (status, metered, state) = *response.lock().unwrap();
        envelope(
            status,
            serde_json::json!({"data":{"state":state,"updated_at":UPDATED}}),
            metered,
        )
    })
    .await;
    let client = server.client();
    for metered in [false, true] {
        *selection.lock().unwrap() = (200, metered, "trashed");
        assert_eq!(
            client.trash_item(vault, item, None).await.unwrap().outcome,
            TrashOutcome::Trashed
        );
        *selection.lock().unwrap() = (200, metered, "already_trashed");
        assert_eq!(
            client
                .trash_item(vault, item, Some(&UPDATED.parse().unwrap()))
                .await
                .unwrap()
                .outcome,
            TrashOutcome::AlreadyTrashed
        );
        for status in [412, 423, 409] {
            *selection.lock().unwrap() = (status, metered, "archived");
            let result = client
                .trash_item(vault, item, Some(&UPDATED.parse().unwrap()))
                .await;
            match status {
                412 => assert!(matches!(result, Err(ResolverError::Stale))),
                423 => assert!(matches!(result, Err(ResolverError::Rotating))),
                // Trash's 409 is archived, not a key-version failure.
                409 => assert!(matches!(
                    result,
                    Err(ResolverError::ServerError { status: 409, .. })
                )),
                _ => unreachable!(),
            }
        }
    }
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 10);
    for (i, req) in requests.iter().enumerate() {
        if i % 5 == 0 {
            assert!(!req.headers.contains_key("if-match"));
        } else {
            assert_eq!(req.headers["if-match"], format!("W/\"{UPDATED}\""));
        }
        assert_ne!(req.method, "DELETE");
    }
}

#[tokio::test]
async fn item_revisions_preserve_offsets_and_fractional_precision_across_reads_and_writes() {
    const READ: &str = "2026-10-17T18:04:56.123400+05:30";
    const CREATED: &str = "2026-10-17T08:34:56.000000-04:00";
    const PATCHED: &str = "2026-10-17T18:04:57.120000+05:30";
    const ALREADY_TRASHED: &str = "2026-10-17T08:34:58.000100-04:00";
    let vault = Uuid::new_v4();
    let item = Uuid::new_v4();
    let key = generate_vault_key();
    for metered in [false, true] {
        let record = item_record(&key, vault, item);
        let outcome = Arc::new(Mutex::new(false));
        let already_trashed = outcome.clone();
        let server = FakeServer::start(move |req| {
            let mut record = record.clone();
            let body = if req.path.ends_with("/trash") {
                let already = *already_trashed.lock().unwrap();
                serde_json::json!({"data": {
                    "state": if already { "already_trashed" } else { "trashed" },
                    "updated_at": if already { ALREADY_TRASHED } else { PATCHED },
                }})
            } else {
                record["updated_at"] = serde_json::json!(match req.method.as_str() {
                    "POST" => CREATED,
                    "PATCH" => PATCHED,
                    _ => READ,
                });
                if req.path.ends_with("/items") && req.method == "GET" {
                    serde_json::json!({"data": [record]})
                } else {
                    serde_json::json!({"data": record})
                }
            };
            envelope(200, body, metered)
        })
        .await;
        let client = server.client();
        let read = client.get_item(vault, item, &key).await.unwrap();
        assert_eq!(read.updated_at.as_str(), READ);
        let summaries = client.list_items(vault, &key).await.unwrap();
        assert_eq!(summaries[0].updated_at.as_str(), READ);
        let created = client
            .create_item_with_id(vault, item, &key, note(), "Synthetic", &[], false, false, 1)
            .await
            .unwrap();
        assert_eq!(created.as_str(), CREATED);
        let patched = client
            .update_item(
                vault,
                item,
                &key,
                note(),
                "Synthetic",
                &[],
                None,
                false,
                1,
                Some(&read.updated_at),
            )
            .await
            .unwrap();
        assert_eq!(patched.as_str(), PATCHED);
        let trashed = client
            .trash_item(vault, item, Some(&created))
            .await
            .unwrap();
        assert_eq!(trashed.outcome, TrashOutcome::Trashed);
        assert_eq!(trashed.updated_at.as_str(), PATCHED);
        *outcome.lock().unwrap() = true;
        let already = client
            .trash_item(vault, item, Some(&patched))
            .await
            .unwrap();
        assert_eq!(already.outcome, TrashOutcome::AlreadyTrashed);
        assert_eq!(already.updated_at.as_str(), ALREADY_TRASHED);
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 7, "write revisions come from responses");
        assert_eq!(requests[4].headers["if-match"], format!("W/\"{READ}\""));
        assert_eq!(requests[5].headers["if-match"], format!("W/\"{CREATED}\""));
        assert_eq!(requests[6].headers["if-match"], format!("W/\"{PATCHED}\""));
    }
}

#[tokio::test]
async fn trash_requires_a_recognized_outcome_and_a_valid_response_revision() {
    let vault = Uuid::new_v4();
    let item = Uuid::new_v4();
    let body = Arc::new(Mutex::new(serde_json::Value::Null));
    let selected = body.clone();
    for metered in [false, true] {
        let response = selected.clone();
        let server = FakeServer::start(move |req| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.path, format!("/vaults/{vault}/items/{item}/trash"));
            let body = serde_json::json!({"data": *response.lock().unwrap()});
            envelope(200, body, metered)
        })
        .await;
        let client = server.client();
        let revision: ItemRevision = UPDATED.parse().unwrap();
        for state in ["trashed", "already_trashed"] {
            for invalid in [
                None,
                Some(serde_json::Value::Null),
                Some(serde_json::json!(42)),
                Some(serde_json::json!("invalid")),
                Some(serde_json::json!("2026-02-30T00:00:00Z")),
            ] {
                let mut response = serde_json::json!({"state": state});
                if let Some(value) = invalid {
                    response["updated_at"] = value;
                }
                *body.lock().unwrap() = response;
                let result = client.trash_item(vault, item, Some(&revision)).await;
                assert!(matches!(result, Err(ResolverError::Malformed(_))));
            }
        }
        for invalid in [
            serde_json::json!({"updated_at": UPDATED}),
            serde_json::json!({"state": "archived", "updated_at": UPDATED}),
        ] {
            *body.lock().unwrap() = invalid;
            let result = client.trash_item(vault, item, None).await;
            assert!(matches!(result, Err(ResolverError::Malformed(_))));
        }
        assert_eq!(server.requests.lock().unwrap().len(), 12);
    }
}

#[tokio::test]
async fn item_reads_and_writes_reject_missing_or_invalid_revisions() {
    let vault = Uuid::new_v4();
    let item = Uuid::new_v4();
    let key = generate_vault_key();
    for invalid in [
        None,
        Some(serde_json::Value::Null),
        Some(serde_json::json!(42)),
        Some(serde_json::json!("invalid")),
        Some(serde_json::json!("2026-02-30T00:00:00Z")),
    ] {
        let read_invalid = Arc::new(Mutex::new(true));
        let selected = read_invalid.clone();
        let record = item_record(&key, vault, item);
        let server = FakeServer::start(move |req| {
            let mut record = record.clone();
            if req.method != "GET" || *selected.lock().unwrap() {
                match &invalid {
                    Some(value) => record["updated_at"] = value.clone(),
                    None => {
                        record.as_object_mut().unwrap().remove("updated_at");
                    }
                }
            }
            let body = if req.path.ends_with("/items") && req.method == "GET" {
                serde_json::json!({"data": [record]})
            } else {
                serde_json::json!({"data": record})
            };
            envelope(200, body, true)
        })
        .await;
        let client = server.client();
        let read = client.get_item(vault, item, &key).await;
        assert!(matches!(read, Err(ResolverError::Malformed(_))));
        let listed = client.list_items(vault, &key).await;
        assert!(matches!(listed, Err(ResolverError::Malformed(_))));
        *read_invalid.lock().unwrap() = false;
        let created = client
            .create_item_with_id(vault, item, &key, note(), "Synthetic", &[], false, false, 1)
            .await;
        assert!(matches!(created, Err(ResolverError::Malformed(_))));
        let updated = client
            .update_item(
                vault,
                item,
                &key,
                note(),
                "Synthetic",
                &[],
                None,
                false,
                1,
                None,
            )
            .await;
        assert!(matches!(updated, Err(ResolverError::Malformed(_))));
    }
}

#[tokio::test]
async fn attachments_round_trip_through_http_with_shared_crypto_and_both_id_bindings() {
    let vault = Uuid::new_v4();
    let item = Uuid::new_v4();
    let key = generate_vault_key();
    let stored = Arc::new(Mutex::new(serde_json::Value::Null));
    let database = stored.clone();
    let server = FakeServer::start(move |req| {
        let collection = format!("/vaults/{vault}/items/{item}/attachments");
        assert!(req.path.starts_with(&collection));
        let mut stored = database.lock().unwrap();
        match req.method.as_str() {
            "POST" => {
                assert_eq!(req.path, collection);
                *stored = req.body.clone();
                stored["item_id"] = serde_json::json!(item);
                stored["size_bytes"] =
                    serde_json::json!(B64.decode(stored["blob"].as_str().unwrap()).unwrap().len());
                stored["created_at"] = serde_json::json!(UPDATED);
                let mut view = stored.clone();
                view.as_object_mut().unwrap().remove("blob");
                (200, serde_json::json!({"data":view}))
            }
            "GET" if req.path == collection => {
                let mut view = stored.clone();
                view.as_object_mut().unwrap().remove("blob");
                (200, serde_json::json!({"data":[view]}))
            }
            "GET" => (
                200,
                serde_json::json!({"data":{"status":200,"body":{"data":*stored}}}),
            ),
            "DELETE" => {
                *stored = serde_json::Value::Null;
                (200, serde_json::json!({"data":{}}))
            }
            _ => panic!("unexpected attachment method"),
        }
    })
    .await;
    let client = server.client();
    let bytes = b"synthetic binary payload\0\xff";
    let uploaded = client
        .put_attachment(
            vault,
            item,
            &key,
            AttachmentUpload {
                filename: Zeroizing::new("synthetic attachment.bin".into()),
                content_type: Some(Zeroizing::new("application/octet-stream".into())),
                bytes: Zeroizing::new(bytes.to_vec()),
            },
        )
        .await
        .unwrap();
    let id = uploaded.attachment_id;
    assert_eq!(uploaded.size_bytes, bytes.len() as u64);
    let original = stored.lock().unwrap().clone();
    let decode = |name: &str| B64.decode(original[name].as_str().unwrap()).unwrap();
    // Verify producer wire independently through the same shared primitives used by UI clients.
    let attachment_key = attachment::unwrap_attachment_key(
        &key,
        item.as_bytes(),
        id.as_bytes(),
        &decode("wrapped_content_key"),
    )
    .unwrap();
    assert_eq!(
        attachment::decrypt_blob(
            &attachment_key,
            item.as_bytes(),
            id.as_bytes(),
            &decode("blob")
        )
        .unwrap(),
        bytes
    );
    assert_eq!(
        attachment::decrypt_filename(
            &key,
            item.as_bytes(),
            id.as_bytes(),
            &decode("filename_ciphertext")
        )
        .unwrap(),
        "synthetic attachment.bin"
    );
    assert_eq!(
        attachment::decrypt_content_type(
            &key,
            item.as_bytes(),
            id.as_bytes(),
            &decode("content_type_ciphertext")
        )
        .unwrap(),
        "application/octet-stream"
    );
    for (wrong_item, wrong_attachment) in [(Uuid::new_v4(), id), (item, Uuid::new_v4())] {
        assert!(
            attachment::unwrap_attachment_key(
                &key,
                wrong_item.as_bytes(),
                wrong_attachment.as_bytes(),
                &decode("wrapped_content_key")
            )
            .is_err()
        );
        assert!(
            attachment::decrypt_blob(
                &attachment_key,
                wrong_item.as_bytes(),
                wrong_attachment.as_bytes(),
                &decode("blob")
            )
            .is_err()
        );
        assert!(
            attachment::decrypt_filename(
                &key,
                wrong_item.as_bytes(),
                wrong_attachment.as_bytes(),
                &decode("filename_ciphertext")
            )
            .is_err()
        );
        assert!(
            attachment::decrypt_content_type(
                &key,
                wrong_item.as_bytes(),
                wrong_attachment.as_bytes(),
                &decode("content_type_ciphertext")
            )
            .is_err()
        );
    }
    let listed = client.list_attachments(vault, item, &key).await.unwrap();
    assert_eq!(listed[0].attachment_id, id);
    assert_eq!(&*listed[0].filename, &*uploaded.filename);
    let downloaded = client.get_attachment(vault, item, id, &key).await.unwrap();
    assert_eq!(&*downloaded.bytes, bytes);
    // A different id in the response must fail even before decrypting.
    stored.lock().unwrap()["attachment_id"] = serde_json::json!(Uuid::new_v4());
    assert!(matches!(
        client.get_attachment(vault, item, id, &key).await,
        Err(ResolverError::ResponseMismatch)
    ));
    *stored.lock().unwrap() = original.clone();
    stored.lock().unwrap()["item_id"] = serde_json::json!(Uuid::new_v4());
    assert!(matches!(
        client.get_attachment(vault, item, id, &key).await,
        Err(ResolverError::ResponseMismatch)
    ));
    // Matching returned ids cannot disguise ciphertext bound to another attachment.
    *stored.lock().unwrap() = original.clone();
    stored.lock().unwrap()["filename_ciphertext"] =
        serde_json::json!(B64.encode(attachment::encrypt_filename(
            &key,
            item.as_bytes(),
            Uuid::new_v4().as_bytes(),
            "synthetic swapped name"
        )));
    assert!(matches!(
        client.get_attachment(vault, item, id, &key).await,
        Err(ResolverError::Crypto(_))
    ));
    *stored.lock().unwrap() = original;
    client.delete_attachment(vault, item, id).await.unwrap();
    assert!(stored.lock().unwrap().is_null());
    let requests = server.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .filter(|r| r.method == "DELETE")
            .all(|r| r.path.ends_with(&format!("/attachments/{id}")))
    );
    let post = requests
        .iter()
        .find(|r| r.method == "POST")
        .unwrap()
        .body
        .to_string();
    assert!(!post.contains("synthetic attachment.bin"));
    assert!(!post.contains("synthetic binary payload"));
}

#[tokio::test]
async fn moving_an_item_trashes_the_source_and_never_hard_deletes_it() {
    let source = Uuid::new_v4();
    let target = Uuid::new_v4();
    let item = Uuid::new_v4();
    let source_key = generate_vault_key();
    let target_key = generate_vault_key();
    let mut record = item_record(&source_key, source, item);
    // A concurrent owner may already have trashed the source.
    record["trashed_at"] = serde_json::json!(TRASHED);
    let outcome = Arc::new(Mutex::new("already_trashed"));
    let selected = outcome.clone();
    let server = FakeServer::start(move |request| {
        let item_path = format!("/vaults/{source}/items/{item}");
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", path) if path == item_path => (200, serde_json::json!({"data": record})),
            ("POST", path) if path == format!("/vaults/{target}/items") => {
                (200, serde_json::json!({"data": {}}))
            }
            ("POST", path) if path == format!("{item_path}/trash") => {
                let state = *selected.lock().unwrap();
                (
                    200,
                    serde_json::json!({"data": {"state": state, "updated_at": UPDATED}}),
                )
            }
            _ => panic!("unexpected method or route"),
        }
    })
    .await;
    let client = server.client();
    for state in ["already_trashed", "trashed"] {
        *outcome.lock().unwrap() = state;
        server.requests.lock().unwrap().clear();
        let copied = client
            .move_item(source, item, &source_key, target, &target_key, 1)
            .await
            .unwrap();
        assert_ne!(copied, item);
        let requests = server.requests.lock().unwrap();
        let routes: Vec<_> = requests
            .iter()
            .map(|r| (r.method.as_str(), r.path.as_str()))
            .collect();
        let created = format!("/vaults/{target}/items");
        let trashed = format!("/vaults/{source}/items/{item}/trash");
        assert_eq!(
            routes,
            [
                ("GET", format!("/vaults/{source}/items/{item}").as_str()),
                ("POST", created.as_str()),
                ("POST", trashed.as_str()),
            ]
        );
        let create = &requests[1].body;
        assert_eq!(create["item_id"], copied.to_string());
        // The copy is sealed for the target vault under the new item id.
        let title = B64
            .decode(create["title_ciphertext"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            decrypt_title(&target_key, copied.as_bytes(), &title).unwrap(),
            "Synthetic fixture title"
        );
        assert!(decrypt_title(&source_key, copied.as_bytes(), &title).is_err());
        assert!(requests.iter().all(|r| r.method != "DELETE"));
    }
}

/// Direct transport can use a caller-authorized internal HTTP endpoint.
const INTERNAL_URL: &str = "http://vault.example.internal:8080/api";

#[tokio::test]
async fn direct_vault_client_accepts_internal_http_and_refuses_proxies_and_redirects() {
    for (network, url, accepted) in [
        (ResolverNetwork::Direct, INTERNAL_URL, true),
        (ResolverNetwork::HostEnvironment, INTERNAL_URL, false),
        (
            ResolverNetwork::Direct,
            "https://vault.example.test/service",
            true,
        ),
        (
            ResolverNetwork::HostEnvironment,
            "https://vault.example.test/service",
            true,
        ),
        (
            ResolverNetwork::Direct,
            "http://user@vault.example.internal:8080/service",
            false,
        ),
        (
            ResolverNetwork::Direct,
            "http://user:secret@vault.example.internal:8080/service",
            false,
        ),
        (
            ResolverNetwork::Direct,
            "http://vault.example.internal:8080/service?token=value",
            false,
        ),
        (
            ResolverNetwork::Direct,
            "http://vault.example.internal:8080/service#fragment",
            false,
        ),
        (
            ResolverNetwork::Direct,
            "ftp://vault.example.test/service",
            false,
        ),
    ] {
        let result = VaultClient::new(config(url, network));
        assert_eq!(result.is_ok(), accepted, "{network:?}: {url}");
        if !accepted {
            assert!(matches!(result, Err(ResolverError::InvalidUri(_))));
        }
    }

    // Proxy settings are process-wide, so each mode runs in a child process
    // with every proxy variable pointing at a fake proxy.
    let target = FakeServer::start(|_| (302, serde_json::json!({}))).await;
    let proxy = FakeServer::start(|_| (418, serde_json::json!({}))).await;
    for mode in ["direct", "host"] {
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "vault_network_child", "--nocapture"])
            .env("SEREN_VAULT_NETWORK_TEST", mode)
            .env("SEREN_VAULT_NETWORK_TEST_URL", &target.url)
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
            child.env(name, &proxy.url);
        }
        let output = tokio::time::timeout(Duration::from_secs(40), child.output())
            .await
            .unwrap()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{mode}: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // Only the host-environment client used the proxy. The direct client
    // reached the target once and did not follow its redirect.
    assert_eq!(proxy.requests.lock().unwrap().len(), 1);
    let reached = target.requests.lock().unwrap();
    assert_eq!(reached.len(), 1);
    assert_eq!(reached[0].path, "/sync");
}

/// Runs only as the child process of the network test above.
#[tokio::test]
async fn vault_network_child() {
    let Ok(mode) = std::env::var("SEREN_VAULT_NETWORK_TEST") else {
        return;
    };
    let network = match mode.as_str() {
        "direct" => ResolverNetwork::Direct,
        "host" => ResolverNetwork::HostEnvironment,
        _ => panic!("invalid test mode"),
    };
    let url = std::env::var("SEREN_VAULT_NETWORK_TEST_URL").unwrap();
    let result = VaultClient::new(config(&url, network))
        .unwrap()
        .list_vaults()
        .await;
    // Direct mode surfaces the target's redirect; host mode got the proxy's answer.
    let expected = if network == ResolverNetwork::Direct {
        302
    } else {
        418
    };
    assert!(
        matches!(result, Err(ResolverError::ServerError { status, .. }) if status == expected),
        "{mode}: {result:?}"
    );
}

/// A version-5 shaped id, standing in for a caller-derived deterministic id.
const CHOSEN_ID: u128 = 0x6f0c9e5a_8f3b_5c1d_9a2e_4b7c1d3e5f70;

#[tokio::test]
async fn create_with_a_chosen_id_sends_that_id_and_favorite_and_returns_updated_at() {
    let vault = Uuid::new_v4();
    let item = Uuid::from_u128(CHOSEN_ID);
    let key = generate_vault_key();
    let reply = Arc::new(Mutex::new((200u16, false, item)));
    let selected = reply.clone();
    let server = FakeServer::start(move |req| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, format!("/vaults/{vault}/items"));
        let (status, metered, returned) = *selected.lock().unwrap();
        envelope(
            status,
            if status == 200 {
                serde_json::json!({"data": item_record(&generate_vault_key(), vault, returned)})
            } else {
                serde_json::json!({"error": {"message": "synthetic upstream error"}})
            },
            metered,
        )
    })
    .await;
    let client = server.client();
    let updated_at = client
        .create_item_with_id(
            vault,
            item,
            &key,
            note(),
            "Synthetic chosen title",
            &[],
            true,
            true,
            1,
        )
        .await
        .unwrap();
    assert_eq!(updated_at, UPDATED.parse::<ItemRevision>().unwrap());
    let sent = server.requests.lock().unwrap()[0].clone();
    assert_eq!(sent.body["item_id"], item.to_string());
    assert_eq!(sent.body["sensitive"], true);
    let decode = |name: &str| B64.decode(sent.body[name].as_str().unwrap()).unwrap();
    assert_eq!(
        decrypt_metadata_json(&key, item.as_bytes(), &decode("metadata_ciphertext")).unwrap(),
        r#"{"item_kind":"secure_note","favorite":true,"sensitive":true,"reprompt":false}"#
    );
    assert_eq!(
        decrypt_title(&key, item.as_bytes(), &decode("title_ciphertext")).unwrap(),
        "Synthetic chosen title"
    );
    for metered in [false, true] {
        for (status, returned) in [(200, Uuid::new_v4()), (423, item), (409, item)] {
            *reply.lock().unwrap() = (status, metered, returned);
            let result = client
                .create_item_with_id(
                    vault,
                    item,
                    &key,
                    note(),
                    "Synthetic chosen title",
                    &[],
                    true,
                    true,
                    1,
                )
                .await;
            match status {
                200 => assert!(matches!(result, Err(ResolverError::ResponseMismatch))),
                423 => assert!(matches!(result, Err(ResolverError::Rotating))),
                // Duplicate id and key version mismatch share an unlabeled 409.
                409 => assert!(matches!(
                    result,
                    Err(ResolverError::ServerError { status: 409, .. })
                )),
                _ => unreachable!(),
            }
        }
    }
}

#[tokio::test]
async fn existing_create_keeps_random_ids_and_unfavorited_metadata() {
    let vault = Uuid::new_v4();
    let key = generate_vault_key();
    let server = FakeServer::start(move |req| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, format!("/vaults/{vault}/items"));
        (200, serde_json::json!({"data": {}}))
    })
    .await;
    let client = server.client();
    let mut ids = Vec::new();
    for _ in 0..2 {
        ids.push(
            client
                .create_item(vault, &key, note(), "Synthetic title", &[], false, 1)
                .await
                .unwrap(),
        );
    }
    assert_ne!(ids[0], ids[1]);
    let requests = server.requests.lock().unwrap();
    for (id, req) in ids.iter().zip(requests.iter()) {
        assert_eq!(id.get_version(), Some(uuid::Version::Random));
        assert_eq!(req.body["item_id"], id.to_string());
        // The v0.6.0 request shape: no new field is sent.
        let mut fields: Vec<_> = req.body.as_object().unwrap().keys().cloned().collect();
        fields.sort();
        assert_eq!(
            fields,
            [
                "content_ciphertext",
                "content_key_wrap",
                "item_id",
                "metadata_ciphertext",
                "sensitive",
                "title_blind_index",
                "title_ciphertext",
                "wrapping_key_version",
            ]
        );
        let metadata = B64
            .decode(req.body["metadata_ciphertext"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            decrypt_metadata_json(&key, id.as_bytes(), &metadata).unwrap(),
            r#"{"item_kind":"secure_note","favorite":false,"sensitive":false,"reprompt":false}"#
        );
    }
}

#[tokio::test]
async fn update_sets_or_keeps_favorite_and_returns_updated_at() {
    const PATCHED: &str = "2026-10-17T12:36:07.000001Z";
    let vault = Uuid::new_v4();
    let item = Uuid::new_v4();
    let key = generate_vault_key();
    let stored = item_record_with_metadata(
        &key,
        vault,
        item,
        r#"{"item_kind":"secure_note","favorite":false,"reprompt":true,"sensitive":false}"#,
    );
    let reply = Arc::new(Mutex::new((200u16, item)));
    let selected = reply.clone();
    let server = FakeServer::start(move |req| {
        assert_eq!(req.path, format!("/vaults/{vault}/items/{item}"));
        if req.method == "GET" {
            return (200, serde_json::json!({"data": stored}));
        }
        assert_eq!(req.method, "PATCH");
        let (status, returned) = *selected.lock().unwrap();
        if status != 200 {
            return (
                status,
                serde_json::json!({"error": {"message": "synthetic"}}),
            );
        }
        let mut patched = item_record(&generate_vault_key(), vault, returned);
        patched["updated_at"] = serde_json::json!(PATCHED);
        (200, serde_json::json!({"data": patched}))
    })
    .await;
    let client = server.client();
    let revision: ItemRevision = UPDATED.parse().unwrap();
    let revision = &revision;
    for (favorite, if_match, expected) in [
        (Some(true), None, true),
        (None, Some(revision), false),
        (Some(false), Some(revision), false),
    ] {
        let updated_at = client
            .update_item(
                vault,
                item,
                &key,
                note(),
                "Synthetic edited title",
                &[],
                favorite,
                false,
                1,
                if_match,
            )
            .await
            .unwrap();
        assert_eq!(updated_at, PATCHED.parse::<ItemRevision>().unwrap());
        let patch = server.requests.lock().unwrap().last().unwrap().clone();
        match if_match {
            Some(_) => assert_eq!(patch.headers["if-match"], format!("W/\"{UPDATED}\"")),
            None => assert!(!patch.headers.contains_key("if-match")),
        }
        let metadata = B64
            .decode(patch.body["metadata_ciphertext"].as_str().unwrap())
            .unwrap();
        let metadata: serde_json::Value =
            serde_json::from_str(&decrypt_metadata_json(&key, item.as_bytes(), &metadata).unwrap())
                .unwrap();
        assert_eq!(metadata["favorite"], expected, "{favorite:?}");
        assert_eq!(metadata["reprompt"], true);
    }
    for (status, returned) in [(412, item), (200, Uuid::new_v4())] {
        *reply.lock().unwrap() = (status, returned);
        let result = client
            .update_item(
                vault,
                item,
                &key,
                note(),
                "Synthetic edited title",
                &[],
                None,
                false,
                1,
                Some(revision),
            )
            .await;
        match status {
            412 => assert!(matches!(result, Err(ResolverError::Stale))),
            _ => assert!(matches!(result, Err(ResolverError::ResponseMismatch))),
        }
    }
}

#[tokio::test]
async fn vaults_report_only_the_callers_own_active_access() {
    let caller = Uuid::new_v4();
    let other = Uuid::new_v4();
    let kem = IdentityKemKeypair::generate();
    let vaults: Vec<(Uuid, VaultKey)> = (0..7)
        .map(|_| (Uuid::new_v4(), generate_vault_key()))
        .collect();
    let id = |i: usize| vaults[i].0;
    let records: Vec<_> = vaults
        .iter()
        .map(|(vault, key)| {
            serde_json::json!({
                "vault_id": vault,
                "name_ciphertext": B64.encode(encrypt_vault_name(key, vault.as_bytes(), "Synthetic vault")),
                "vault_key_version": 1,
                "wrapped_vault_key": B64.encode(wrap_vault_key_for_identity(key, &kem.public)),
            })
        })
        .collect();
    let row = |vault: Uuid, identity: Uuid, level: &str, revoked_at: Option<&str>| {
        serde_json::json!({
            "vault_id": vault,
            "identity_id": identity,
            "access_level": level,
            "revoked_at": revoked_at,
            "granted_at": UPDATED,
            "granted_signature": "c3ludGhldGlj",
        })
    };
    let mut missing_revoked_at = row(id(4), caller, "write", None);
    missing_revoked_at
        .as_object_mut()
        .unwrap()
        .remove("revoked_at");
    let mut missing_level = row(id(5), caller, "write", None);
    missing_level
        .as_object_mut()
        .unwrap()
        .remove("access_level");
    let mut bad_vault_id = row(id(6), caller, "admin", None);
    bad_vault_id["vault_id"] = serde_json::json!("synthetic-not-a-uuid");
    let memberships = serde_json::json!([
        // 0: the caller's write row, another identity's admin row, and the
        // caller's own revoked admin row.
        row(id(0), caller, "write", None),
        row(id(0), other, "admin", None),
        row(id(0), caller, "admin", Some(TRASHED)),
        // 1: shared from another organization, so no caller row.
        row(id(1), other, "write", None),
        // 2: only a revoked caller row.
        row(id(2), caller, "write", Some(TRASHED)),
        // 3: a level this client does not know.
        row(id(3), caller, "owner", None),
        // 4 and 5: a required field is missing.
        missing_revoked_at,
        missing_level,
        // 6: an unparseable vault id, then rows of the wrong type.
        bad_vault_id,
        "synthetic unexpected row",
        7,
        null,
    ]);
    let server = FakeServer::start(move |req| {
        assert_eq!((req.method.as_str(), req.path.as_str()), ("GET", "/sync"));
        (
            200,
            serde_json::json!({"data": {
                "vaults": records,
                "item_overviews": [],
                "identities": [],
                "memberships": memberships,
                "server_time": UPDATED,
            }}),
        )
    })
    .await;
    let client = VaultClient::new(VaultClientConfig {
        caller_identity_id: caller,
        key_source: VaultKeySource::AgentKey {
            kem_private: kem.private.clone(),
        },
        ..config(&server.url, ResolverNetwork::HostEnvironment)
    })
    .unwrap();
    let listed = client.list_vaults().await.unwrap();
    assert_eq!(listed.len(), vaults.len());
    for (i, vault) in listed.iter().enumerate() {
        assert_eq!(vault.vault_id, id(i));
        assert_eq!(vault.name, "Synthetic vault");
        let expected = (i == 0).then_some(VaultAccessLevel::Write);
        assert_eq!(vault.access, expected, "vault {i}");
    }
}

/// SHA-256 of `b"abc"` (FIPS 180-2, appendix B.1).
const ABC_SHA256: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

fn upload(name: &str, bytes: &[u8]) -> AttachmentUpload {
    AttachmentUpload {
        filename: Zeroizing::new(name.into()),
        content_type: Some(Zeroizing::new("application/octet-stream".into())),
        bytes: Zeroizing::new(bytes.to_vec()),
    }
}

/// The fake service's stored rows and its next answers to the two guarded writes.
struct AttachmentService {
    rows: Vec<serde_json::Value>,
    create: (u16, Option<&'static str>),
    delete: (u16, Option<&'static str>, &'static str),
    metered: bool,
    /// Sent as `error.item_updated_at` on every create refusal, so outcomes
    /// that must report `None` are shown to ignore a present revision.
    duplicate_revision: Option<&'static str>,
}

fn coded_error(status: u16, kind: Option<&str>) -> serde_json::Value {
    let mut error = serde_json::json!({"message": "synthetic refusal", "code": status});
    if let Some(kind) = kind {
        error["kind"] = serde_json::json!(kind);
    }
    serde_json::json!({ "error": error })
}

#[tokio::test]
async fn attachment_writes_send_the_chosen_id_and_both_guards_and_map_every_outcome() {
    let vault = Uuid::new_v4();
    let item = Uuid::new_v4();
    let chosen = Uuid::from_u128(CHOSEN_ID);
    let key = generate_vault_key();
    let revision: ItemRevision = UPDATED.parse().unwrap();
    let revision = &revision;
    let collection = format!("/vaults/{vault}/items/{item}/attachments");
    let deletion = format!("{collection}/{chosen}/deletion");
    let state = Arc::new(Mutex::new(AttachmentService {
        rows: Vec::new(),
        create: (200, None),
        delete: (200, None, "deleted"),
        metered: false,
        duplicate_revision: Some(DUPLICATE_REVISION),
    }));
    let service = state.clone();
    let routes = (collection.clone(), deletion.clone());
    let server = FakeServer::start(move |req| {
        let mut service = service.lock().unwrap();
        let metered = service.metered;
        match req.method.as_str() {
            "GET" if req.path == routes.0 => (200, serde_json::json!({"data": service.rows})),
            "POST" if req.path == routes.0 => {
                let (status, kind) = service.create;
                if status != 200 {
                    let mut error = coded_error(status, kind);
                    if let Some(revision) = service.duplicate_revision {
                        error["error"]["item_updated_at"] = serde_json::json!(revision);
                    }
                    return envelope(status, error, metered);
                }
                let mut row = req.body.clone();
                let blob = row.as_object_mut().unwrap().remove("blob").unwrap();
                row["item_id"] = serde_json::json!(item);
                row["size_bytes"] =
                    serde_json::json!(B64.decode(blob.as_str().unwrap()).unwrap().len());
                row["created_at"] = serde_json::json!(UPDATED);
                if row.get("digest_ciphertext").is_none() {
                    row["digest_ciphertext"] = serde_json::Value::Null;
                }
                service.rows = vec![row.clone()];
                row["item_updated_at"] = serde_json::json!(UPDATED);
                envelope(200, serde_json::json!({"data": row}), metered)
            }
            "POST" if req.path == routes.1 => {
                let (status, kind, outcome) = service.delete;
                if status != 200 {
                    return envelope(status, coded_error(status, kind), metered);
                }
                envelope(
                    200,
                    serde_json::json!({"data": {"state": outcome, "item_updated_at": UPDATED}}),
                    metered,
                )
            }
            _ => panic!("unexpected attachment method or route"),
        }
    })
    .await;
    let client = &server.client();
    let key = &key;
    let put = move |name: &'static str, bytes: &'static [u8]| {
        client.put_attachment_with_id(vault, item, chosen, key, upload(name, bytes), revision)
    };
    let delete = move |expected: [u8; 32]| async move {
        client
            .conditional_delete_attachment(vault, item, chosen, key, &expected, revision)
            .await
    };
    let request_count = || server.requests.lock().unwrap().len();

    // Created: the chosen id, the parent-revision guard and a sealed digest.
    let created = put("synthetic mirrored file.bin", b"abc").await.unwrap();
    assert_eq!(created.item_updated_at, Some(revision.clone()));
    let AttachmentPutOutcome::Created(summary) = created.outcome else {
        panic!("expected a created attachment");
    };
    assert_eq!(summary.attachment_id, chosen);
    assert_eq!(summary.sha256, Some(ABC_SHA256));
    let sent = server.requests.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        (sent.method.as_str(), sent.path.as_str()),
        ("POST", collection.as_str())
    );
    assert_eq!(sent.headers["if-match"], format!("W/\"{UPDATED}\""));
    assert_eq!(sent.body["attachment_id"], chosen.to_string());
    assert!(
        !sent
            .body
            .to_string()
            .contains("synthetic mirrored file.bin")
    );
    let decode = |name: &str| B64.decode(sent.body[name].as_str().unwrap()).unwrap();
    let attachment_key = attachment::unwrap_attachment_key(
        key,
        item.as_bytes(),
        chosen.as_bytes(),
        &decode("wrapped_content_key"),
    )
    .unwrap();
    let digest = decode("digest_ciphertext");
    assert_eq!(
        attachment::decrypt_digest(&attachment_key, item.as_bytes(), chosen.as_bytes(), &digest)
            .unwrap(),
        ABC_SHA256
    );
    // The digest is bound to this attachment and never opens as a blob.
    assert!(
        attachment::decrypt_digest(
            &attachment_key,
            item.as_bytes(),
            Uuid::new_v4().as_bytes(),
            &digest
        )
        .is_err()
    );
    assert!(
        attachment::decrypt_blob(&attachment_key, item.as_bytes(), chosen.as_bytes(), &digest)
            .is_err()
    );

    // The digest round-trips through the list.
    let listed = client.list_attachments(vault, item, key).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].attachment_id, chosen);
    assert_eq!(listed[0].sha256, Some(ABC_SHA256));
    assert_eq!(&*listed[0].filename, "synthetic mirrored file.bin");
    assert_eq!(listed[0].size_bytes, 3);
    let stored = state.lock().unwrap().rows[0].clone();

    for metered in [false, true] {
        state.lock().unwrap().metered = metered;
        // A retried create of the same file is already present; the 409 means
        // the service matched the parent revision first.
        state.lock().unwrap().create = (409, Some("attachment_already_exists"));
        let retried = put("synthetic mirrored file.bin", b"abc").await.unwrap();
        assert!(matches!(
            retried.outcome,
            AttachmentPutOutcome::AlreadyPresent
        ));
        assert_eq!(
            retried.item_updated_at.as_ref().map(ItemRevision::as_str),
            Some(DUPLICATE_REVISION)
        );
        for invalid in [None, Some("not a revision")] {
            state.lock().unwrap().duplicate_revision = invalid;
            assert!(matches!(
                put("synthetic mirrored file.bin", b"abc").await,
                Err(ResolverError::Malformed(_))
            ));
            // A conflict never reads the revision, so it cannot fail on it.
            let conflict = put("synthetic mirrored file.bin", b"abd").await.unwrap();
            assert!(matches!(conflict.outcome, AttachmentPutOutcome::IdConflict));
            assert_eq!(conflict.item_updated_at, None);
        }
        state.lock().unwrap().duplicate_revision = Some(DUPLICATE_REVISION);
        // A different file, or the same bytes under another name, is a conflict.
        for (name, bytes) in [
            ("synthetic mirrored file.bin", b"abd"),
            ("synthetic renamed file.bin", b"abc"),
        ] {
            let conflict = put(name, bytes).await.unwrap();
            assert!(matches!(conflict.outcome, AttachmentPutOutcome::IdConflict));
            assert_eq!(conflict.item_updated_at, None);
        }
        // Another item using the id needs no list read.
        state.lock().unwrap().create = (409, Some("attachment_id_conflict"));
        let before = request_count();
        let elsewhere = put("synthetic mirrored file.bin", b"abc").await.unwrap();
        assert!(matches!(
            elsewhere.outcome,
            AttachmentPutOutcome::IdConflict
        ));
        assert_eq!(elsewhere.item_updated_at, None);
        assert_eq!(request_count(), before + 1);
        state.lock().unwrap().create = (412, None);
        let stale = put("synthetic mirrored file.bin", b"abc").await.unwrap();
        assert!(matches!(stale.outcome, AttachmentPutOutcome::Stale));
        assert_eq!(stale.item_updated_at, None);
        state.lock().unwrap().create = (423, None);
        assert!(matches!(
            put("synthetic mirrored file.bin", b"abc").await,
            Err(ResolverError::Rotating)
        ));
        // A 409 without a known kind is not guessed at.
        state.lock().unwrap().create = (409, None);
        assert!(matches!(
            put("synthetic mirrored file.bin", b"abc").await,
            Err(ResolverError::ServerError { status: 409, .. })
        ));

        // Deletion sends both guards: the revision and the exact stored digest.
        for (status, kind, outcome, expected) in [
            (200, None, "deleted", AttachmentDeleteOutcome::Deleted),
            (
                200,
                None,
                "already_absent",
                AttachmentDeleteOutcome::AlreadyAbsent,
            ),
            (
                409,
                Some("attachment_digest_mismatch"),
                "",
                AttachmentDeleteOutcome::Mismatch,
            ),
            (412, None, "", AttachmentDeleteOutcome::Stale),
        ] {
            state.lock().unwrap().delete = (status, kind, outcome);
            let deleted = delete(ABC_SHA256).await.unwrap();
            assert_eq!(deleted.outcome, expected);
            let confirmed = (status == 200).then(|| revision.clone());
            assert_eq!(deleted.item_updated_at, confirmed, "{expected:?}");
            let sent = server.requests.lock().unwrap().last().unwrap().clone();
            assert_eq!(
                (sent.method.as_str(), sent.path.as_str()),
                ("POST", deletion.as_str())
            );
            assert_eq!(sent.headers["if-match"], format!("W/\"{UPDATED}\""));
            assert_eq!(
                sent.body,
                serde_json::json!({"expected_digest_ciphertext": stored["digest_ciphertext"]})
            );
        }
        state.lock().unwrap().delete = (423, None, "");
        assert!(matches!(
            delete(ABC_SHA256).await,
            Err(ResolverError::Rotating)
        ));
    }
    state.lock().unwrap().metered = false;

    // A guard that does not name verified stored bytes is a fresh seal: it can
    // never equal the stored digest, so it cannot delete anything.
    let unmatchable = |sent: &Request| {
        let guard = sent.body["expected_digest_ciphertext"].as_str().unwrap();
        assert_ne!(
            Some(guard),
            stored["digest_ciphertext"].as_str(),
            "the stored digest is never sent unverified"
        );
        let guard = B64.decode(guard).unwrap();
        assert_eq!(guard.len(), 2 + 24 + 32 + 16);
        // Sealed under a throwaway key, so it matches nothing stored under the
        // attachment's real key.
        assert!(
            attachment::decrypt_digest(&attachment_key, item.as_bytes(), chosen.as_bytes(), &guard)
                .is_err()
        );
    };
    // Every guarded deletion goes to the service, which checks the parent
    // revision before anything else, so a stale item is reported as stale
    // and the confirmed revision comes from the guarded write, never the list.
    let refusals = [
        (
            409,
            Some("attachment_digest_mismatch"),
            "",
            AttachmentDeleteOutcome::Mismatch,
        ),
        (412, None, "", AttachmentDeleteOutcome::Stale),
    ];
    let guarded_case = |rows: Vec<serde_json::Value>,
                        answer: (u16, Option<&'static str>, &'static str),
                        expected_sha256: [u8; 32],
                        expected: AttachmentDeleteOutcome| {
        let (state, server, unmatchable, deletion) = (&state, &server, &unmatchable, &deletion);
        async move {
            {
                let mut service = state.lock().unwrap();
                service.rows = rows;
                service.delete = answer;
            }
            let before = server.requests.lock().unwrap().len();
            let result = delete(expected_sha256).await.unwrap();
            assert_eq!(result.outcome, expected);
            assert_eq!(
                result.item_updated_at,
                (answer.0 == 200).then(|| revision.clone())
            );
            let requests = server.requests.lock().unwrap();
            assert_eq!(
                requests.len(),
                before + 2,
                "the list, then the guarded deletion"
            );
            let sent = requests.last().unwrap();
            assert_eq!(
                (sent.method.as_str(), sent.path.as_str()),
                ("POST", deletion.as_str())
            );
            assert_eq!(sent.headers["if-match"], format!("W/\"{UPDATED}\""));
            unmatchable(sent);
        }
    };

    // A missing or unopenable digest is unverifiable: listed without a
    // SHA-256, never already present, and never deleted.
    let foreign_digest = B64.encode(attachment::encrypt_digest(
        &attachment_key,
        item.as_bytes(),
        Uuid::new_v4().as_bytes(),
        &ABC_SHA256,
    ));
    for digest in [
        Some(serde_json::Value::Null),
        Some(serde_json::json!(foreign_digest)),
        Some(serde_json::json!("synthetic not base64!")),
        None,
    ] {
        let mut row = stored.clone();
        match digest {
            Some(value) => row["digest_ciphertext"] = value,
            None => {
                row.as_object_mut().unwrap().remove("digest_ciphertext");
            }
        }
        state.lock().unwrap().rows = vec![row.clone()];
        let listed = client.list_attachments(vault, item, key).await.unwrap();
        assert_eq!(listed[0].sha256, None);
        state.lock().unwrap().create = (409, Some("attachment_already_exists"));
        let retried = put("synthetic mirrored file.bin", b"abc").await.unwrap();
        assert!(matches!(retried.outcome, AttachmentPutOutcome::IdConflict));
        assert_eq!(retried.item_updated_at, None);
        for (status, kind, outcome, expected) in refusals {
            guarded_case(
                vec![row.clone()],
                (status, kind, outcome),
                ABC_SHA256,
                expected,
            )
            .await;
        }
    }

    // Another expected digest, and an attachment the item no longer has, are
    // decided by the service too.
    let mut other_digest = ABC_SHA256;
    other_digest[0] ^= 1;
    for (status, kind, outcome, expected) in refusals {
        guarded_case(
            vec![stored.clone()],
            (status, kind, outcome),
            other_digest,
            expected,
        )
        .await;
    }
    for (status, kind, outcome, expected) in [
        (
            200,
            None,
            "already_absent",
            AttachmentDeleteOutcome::AlreadyAbsent,
        ),
        (412, None, "", AttachmentDeleteOutcome::Stale),
    ] {
        guarded_case(Vec::new(), (status, kind, outcome), ABC_SHA256, expected).await;
    }

    // The unguarded upload keeps its v0.6.0 body: no digest and no guard.
    state.lock().unwrap().create = (200, None);
    client
        .put_attachment(vault, item, key, upload("synthetic plain.bin", b"abc"))
        .await
        .unwrap();
    let plain = server.requests.lock().unwrap().last().unwrap().clone();
    assert!(plain.body.get("digest_ciphertext").is_none());
    assert!(!plain.headers.contains_key("if-match"));

    let requests = server.requests.lock().unwrap();
    assert!(requests.iter().all(|r| r.method != "DELETE"));
    assert!(
        requests
            .iter()
            .filter(|r| r.path == deletion)
            .all(|r| r.headers.contains_key("if-match"))
    );
}

#[tokio::test]
async fn empty_attachments_preserve_optional_metadata_and_write_guards_over_http() {
    const EXPECTED: &str = "2026-10-17T18:04:56.123400+05:30";
    const CONFIRMED: &str = "2026-10-17T08:34:57.000100-04:00";
    for metered in [false, true] {
        for content_type in [None, Some("text/plain")] {
            let vault = Uuid::new_v4();
            let item = Uuid::new_v4();
            let id = Uuid::new_v4();
            let key = generate_vault_key();
            let collection = format!("/vaults/{vault}/items/{item}/attachments");
            let deletion = format!("{collection}/{id}/deletion");
            let state = Arc::new(Mutex::new(None::<serde_json::Value>));
            let stored = state.clone();
            let server = FakeServer::start(move |req| {
                let mut stored = stored.lock().unwrap();
                let (status, body) = if req.method == "POST" {
                    assert_eq!(req.headers["if-match"], format!("W/\"{EXPECTED}\""));
                    if req.path == collection {
                        if stored.is_some() {
                            let conflict = serde_json::json!({
                                "error": {"kind": "attachment_already_exists", "item_updated_at": CONFIRMED},
                            });
                            (409, conflict)
                        } else {
                            let mut record = req.body.clone();
                            let bytes = B64.decode(record["blob"].as_str().unwrap()).unwrap();
                            assert_eq!(bytes.len(), 42);
                            record["item_id"] = serde_json::json!(item);
                            record["size_bytes"] = serde_json::json!(bytes.len());
                            record["created_at"] = serde_json::json!(UPDATED);
                            record["item_updated_at"] = serde_json::json!(CONFIRMED);
                            *stored = Some(record.clone());
                            (200, serde_json::json!({"data": record}))
                        }
                    } else {
                        assert_eq!(req.path, deletion);
                        let outcome = if let Some(record) = stored.as_ref() {
                            assert_eq!(
                                req.body["expected_digest_ciphertext"],
                                record["digest_ciphertext"]
                            );
                            *stored = None;
                            "deleted"
                        } else {
                            "already_absent"
                        };
                        let deleted = serde_json::json!({
                            "data": {"state": outcome, "item_updated_at": CONFIRMED},
                        });
                        (200, deleted)
                    }
                } else {
                    assert_eq!(req.method, "GET");
                    if req.path == collection {
                        let listed: Vec<_> = stored.iter().collect();
                        (200, serde_json::json!({"data": listed}))
                    } else {
                        (200, serde_json::json!({"data": stored.as_ref().unwrap()}))
                    }
                };
                envelope(status, body, metered)
            })
            .await;
            let client = server.client();
            let revision = ItemRevision::new(EXPECTED).unwrap();
            let upload = || AttachmentUpload {
                filename: Zeroizing::new("empty.txt".to_owned()),
                content_type: content_type.map(|value| Zeroizing::new(value.to_owned())),
                bytes: Zeroizing::new(Vec::new()),
            };
            let created = client
                .put_attachment_with_id(vault, item, id, &key, upload(), &revision)
                .await
                .unwrap();
            assert_eq!(created.item_updated_at.unwrap().as_str(), CONFIRMED);
            let AttachmentPutOutcome::Created(summary) = created.outcome else {
                panic!("expected a created attachment");
            };
            assert_eq!(summary.size_bytes, 0);
            assert_eq!(
                summary.content_type.as_deref().map(String::as_str),
                content_type
            );
            let digest = attachment::plaintext_digest(b"");
            assert_eq!(summary.sha256, Some(digest));
            let downloaded = client.get_attachment(vault, item, id, &key).await.unwrap();
            assert!(downloaded.bytes.is_empty());
            assert_eq!(
                downloaded
                    .summary
                    .content_type
                    .as_deref()
                    .map(String::as_str),
                content_type
            );
            let duplicate = client
                .put_attachment_with_id(vault, item, id, &key, upload(), &revision)
                .await
                .unwrap();
            assert!(matches!(
                duplicate.outcome,
                AttachmentPutOutcome::AlreadyPresent
            ));
            assert_eq!(duplicate.item_updated_at.unwrap().as_str(), CONFIRMED);
            for expected in [
                AttachmentDeleteOutcome::Deleted,
                AttachmentDeleteOutcome::AlreadyAbsent,
            ] {
                let deleted = client
                    .conditional_delete_attachment(vault, item, id, &key, &digest, &revision)
                    .await
                    .unwrap();
                assert_eq!(deleted.outcome, expected);
                assert_eq!(deleted.item_updated_at.unwrap().as_str(), CONFIRMED);
            }
            assert!(state.lock().unwrap().is_none());
        }
    }
}
