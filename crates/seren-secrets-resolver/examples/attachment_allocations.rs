//! Synthetic attachment codec memory harness; no HTTP requests are performed.
//!
//! Build once with `cargo build --release -p seren-secrets-resolver --example
//! attachment_allocations`, then measure the executable directly with a peak-RSS
//! tool. Run each size and operation in its own process, with concurrency one.
//! `--operation fixture --size N --fixture PATH` writes ciphertext-only JSON for
//! `--operation download --size N --fixture PATH`; generate it in a separate
//! process so upload memory cannot contaminate the download process's peak.
//!
//! Upload includes synthetic plaintext allocation, digest, encrypted metadata,
//! encrypted blob, base64, owned JSON assembly and JSON body serialization.
//! Download includes fixture file read, JSON parsing, metadata/key verification,
//! base64 decoding and authenticated decryption. It excludes HTTP, network and
//! transport buffers; RSS includes runtime startup and the system allocator.
//! Only sizes and timings are printed. No plaintext or keys are written to disk.

use std::{
    env,
    error::Error,
    hint::black_box,
    path::{Path, PathBuf},
    time::Instant,
};

use serde::Deserialize;
use seren_secrets_crypto::{keys::VaultKey, protocol::attachment};
use seren_secrets_resolver::vault::attachments::{
    AttachmentRecord, AttachmentUpload, ENVELOPE_BYTES, MAX_ATTACHMENT_PLAINTEXT_BYTES,
    MAX_METADATA_BYTES, attachment_summary, bounded_decode, decrypt_blob, prepare_upload,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const ITEM_ID: Uuid = Uuid::from_u128(1);
const ATTACHMENT_ID: Uuid = Uuid::from_u128(2);

#[derive(Clone, Copy)]
enum Operation {
    Upload,
    Fixture,
    Download,
}

impl Operation {
    fn name(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Fixture => "fixture",
            Self::Download => "download",
        }
    }
}

struct Arguments {
    operation: Operation,
    size: usize,
    fixture: Option<PathBuf>,
}

fn arguments() -> Result<Arguments, Box<dyn Error>> {
    let mut operation = None;
    let mut size = None;
    let mut fixture = None;
    let mut args = env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or("every argument requires a value")?;
        match flag.as_str() {
            "--operation" if operation.is_none() => {
                operation = Some(match value.as_str() {
                    "upload" => Operation::Upload,
                    "fixture" => Operation::Fixture,
                    "download" => Operation::Download,
                    _ => return Err("operation must be upload, fixture or download".into()),
                });
            }
            "--size" if size.is_none() => size = Some(value.parse::<usize>()?),
            "--fixture" if fixture.is_none() => fixture = Some(PathBuf::from(value)),
            _ => return Err("unknown or duplicate argument".into()),
        }
    }
    let operation = operation.ok_or("--operation is required")?;
    let size = size.ok_or("--size is required (plaintext bytes)")?;
    if !(1..=MAX_ATTACHMENT_PLAINTEXT_BYTES).contains(&size) {
        return Err("size is outside the public attachment plaintext limit".into());
    }
    match operation {
        Operation::Fixture | Operation::Download if fixture.is_none() => {
            return Err("--fixture is required for fixture and download".into());
        }
        Operation::Upload if fixture.is_some() => {
            return Err("--fixture is not used for upload".into());
        }
        _ => {}
    }
    Ok(Arguments {
        operation,
        size,
        fixture,
    })
}

fn upload(vault_key: &VaultKey, size: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let upload = AttachmentUpload {
        filename: Zeroizing::new("synthetic.bin".to_owned()),
        content_type: Some(Zeroizing::new("application/octet-stream".to_owned())),
        bytes: Zeroizing::new(vec![0xa5; size]),
    };
    let digest = attachment::plaintext_digest(&upload.bytes);
    let pending = prepare_upload(vault_key, ITEM_ID, ATTACHMENT_ID, upload, Some(&digest))?;
    let body = serde_json::Value::from(pending.encrypt());
    let serialized = serde_json::to_vec(&body)?;
    black_box(&serialized);
    drop(body);
    Ok(serialized)
}

#[derive(Deserialize)]
struct Fixture {
    attachment_id: Uuid,
    blob: String,
    filename_ciphertext: String,
    content_type_ciphertext: String,
    wrapped_content_key: String,
    digest_ciphertext: Option<String>,
}

fn download(vault_key: &VaultKey, size: usize, path: &Path) -> Result<usize, Box<dyn Error>> {
    let serialized = std::fs::read(path)?;
    let body: serde_json::Value = serde_json::from_slice(&serialized)?;
    // The HTTP helper releases its response byte buffer after JSON parsing.
    drop(serialized);
    let fixture: Fixture = serde_json::from_value(body)?;
    if fixture.attachment_id != ATTACHMENT_ID {
        return Err("fixture attachment id differs".into());
    }
    let record = AttachmentRecord {
        attachment_id: fixture.attachment_id,
        item_id: ITEM_ID,
        filename_ciphertext: fixture.filename_ciphertext,
        content_type_ciphertext: fixture.content_type_ciphertext,
        wrapped_content_key: fixture.wrapped_content_key,
        size_bytes: (size + ENVELOPE_BYTES) as i64,
        created_at: "2026-01-01T00:00:00Z".to_owned(),
        digest_ciphertext: fixture.digest_ciphertext,
    };
    let summary = attachment_summary(vault_key, ITEM_ID, &record)?;
    let key = attachment::unwrap_attachment_key(
        vault_key,
        ITEM_ID.as_bytes(),
        ATTACHMENT_ID.as_bytes(),
        &bounded_decode(&record.wrapped_content_key, MAX_METADATA_BYTES)?,
    )?;
    let bytes = decrypt_blob(
        &key,
        ITEM_ID,
        ATTACHMENT_ID,
        &fixture.blob,
        summary.encrypted_size_bytes,
    )?;
    if bytes.len() != size {
        return Err("fixture plaintext size differs".into());
    }
    black_box(&*bytes);
    drop(bytes);
    drop(key);
    drop(summary);
    drop(record);
    drop(fixture.blob);
    Ok(size)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = arguments()?;
    // Public, fixed synthetic fixture key; never use this key for real data.
    let vault_key = VaultKey::from_bytes([7; 32]);
    let started = Instant::now();
    let output_bytes = match args.operation {
        Operation::Upload => {
            let body = upload(&vault_key, args.size)?;
            let len = body.len();
            drop(body);
            len
        }
        Operation::Fixture => {
            let body = upload(&vault_key, args.size)?;
            std::fs::write(
                args.fixture.as_ref().expect("fixture argument validated"),
                &body,
            )?;
            let len = body.len();
            drop(body);
            len
        }
        Operation::Download => download(
            &vault_key,
            args.size,
            args.fixture.as_ref().expect("fixture argument validated"),
        )?,
    };
    let elapsed_ns = started.elapsed().as_nanos();
    drop(vault_key);
    let report = serde_json::json!({
        "operation": args.operation.name(),
        "plaintext_bytes": args.size,
        "encrypted_bytes": args.size + ENVELOPE_BYTES,
        "output_bytes": output_bytes,
        "elapsed_ns": elapsed_ns,
        "concurrency": 1,
        "measurement": "attachment codec; process peak RSS measured externally",
        "http_included": false,
    });
    println!("{report}");
    Ok(())
}
