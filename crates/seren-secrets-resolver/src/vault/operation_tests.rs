//! SEC-2 HTTP contract tests. All keys and data are generated, synthetic fixtures.

use super::*;
use seren_secrets_crypto::protocol::{
    attachment, item::SecureNoteContent, vault::generate_vault_key,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UPDATED: &str = "2026-10-17T12:34:56.123456Z";
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
                let response = format!(
                    "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
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
        VaultClient::new(VaultClientConfig {
            base_url: self.url.clone(),
            bearer_token: "synthetic-test-token".to_string(),
            key_source: VaultKeySource::AgentKey {
                kem_private: seren_secrets_crypto::keys::IdentityKemKeypair::generate().private,
            },
        })
        .unwrap()
    }
}

fn note() -> ItemContent {
    ItemContent::SecureNote(SecureNoteContent::default())
}

fn item_record(key: &VaultKey, vault: Uuid, item: Uuid) -> serde_json::Value {
    let request =
        build_create_request(key, item, &note(), "Synthetic fixture title", &[], false, 1).unwrap();
    let mut record = serde_json::to_value(request).unwrap();
    record["vault_id"] = serde_json::json!(vault);
    record["updated_at"] = serde_json::json!(UPDATED);
    record["trashed_at"] = serde_json::Value::Null;
    record["metadata_ciphertext"] = serde_json::json!(B64.encode(encrypt_metadata_json(
        key,
        item.as_bytes(),
        r#"{"item_kind":"secure_note","favorite":true,"reprompt":true,"sensitive":false}"#
    )));
    record
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
            let timestamp = (status != 200).then(|| UPDATED.parse().unwrap());
            let result = client
                .update_item(
                    vault,
                    item,
                    &key,
                    note(),
                    "Synthetic edited title",
                    &[],
                    false,
                    1,
                    timestamp,
                )
                .await;
            match status {
                200 => result.unwrap(),
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
        assert_eq!(metadata_flags(&metadata), (true, true));
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
    assert_eq!(read.updated_at, UPDATED.parse::<Timestamp>().unwrap());
    assert_eq!(read.trashed_at, Some(TRASHED.parse::<Timestamp>().unwrap()));
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
            client.trash_item(vault, item, None).await.unwrap(),
            TrashOutcome::Trashed
        );
        *selection.lock().unwrap() = (200, metered, "already_trashed");
        assert_eq!(
            client
                .trash_item(vault, item, Some(UPDATED.parse().unwrap()))
                .await
                .unwrap(),
            TrashOutcome::AlreadyTrashed
        );
        for status in [412, 423, 409] {
            *selection.lock().unwrap() = (status, metered, "archived");
            let result = client
                .trash_item(vault, item, Some(UPDATED.parse().unwrap()))
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
                content_type: Zeroizing::new("application/octet-stream".into()),
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
