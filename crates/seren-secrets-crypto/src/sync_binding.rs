//! Encrypted 1Password sync provenance and byte-exact mirror identity.
//!
//! Compatibility contract: hash `{title,tags,favorite,body}` with recursive
//! RFC 8785 UTF-16 property ordering, no whitespace, and the crate's numeric
//! serialization. String values are NEVER Unicode-normalized, trimmed or folded.
//! Remove ONLY `raw_import.seren_sync`; null and an empty object remain distinct.
//! Changing these rules would make every existing mirror appear edited.
use crate::protocol::item::ItemContent;
use crate::{CryptoError, CryptoResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct SyncBinding {
    pub source: &'static str,
    pub account_id: String,
    pub vault_id: String,
    pub item_id: String,
    pub item_version: u64,
    pub source_updated_at: String,
    pub content_hash: String,
    pub synced_at: String,
}

impl std::fmt::Debug for SyncBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncBinding(<redacted>)")
    }
}
impl<'de> Deserialize<'de> for SyncBinding {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            source: String,
            account_id: String,
            vault_id: String,
            item_id: String,
            item_version: u64,
            source_updated_at: String,
            content_hash: String,
            synced_at: String,
        }
        let wire = Wire::deserialize(d)?;
        if wire.source != "1password" {
            return Err(serde::de::Error::custom("unsupported sync source"));
        }
        Ok(Self {
            source: "1password",
            account_id: wire.account_id,
            vault_id: wire.vault_id,
            item_id: wire.item_id,
            item_version: wire.item_version,
            source_updated_at: wire.source_updated_at,
            content_hash: wire.content_hash,
            synced_at: wire.synced_at,
        })
    }
}

/// Attach to object metadata only. Refusal is content-free and leaves the item unchanged.
pub fn attach(content: &mut ItemContent, binding: &SyncBinding) -> CryptoResult<()> {
    if binding.source != "1password" {
        return Err(CryptoError::Import("unsupported sync source"));
    }
    let (raw, _, _) = content.import_metadata_mut();
    let object = raw
        .as_object_mut()
        .ok_or(CryptoError::Import("sync binding requires object metadata"))?;
    let value =
        serde_json::to_value(binding).map_err(|_| CryptoError::Import("invalid sync binding"))?;
    object.insert("seren_sync".to_owned(), value);
    Ok(())
}

/// Return an unbound clone and any well-formed binding. Other metadata is untouched.
pub fn detach(content: &ItemContent) -> (ItemContent, Option<SyncBinding>) {
    let mut content = content.clone();
    let (raw, _, _) = content.import_metadata_mut();
    let binding = raw
        .as_object_mut()
        .and_then(|m| m.remove("seren_sync"))
        .and_then(|v| serde_json::from_value(v).ok());
    (content, binding)
}

pub fn content_hash(title: &str, tags: &[String], favorite: bool, content: &ItemContent) -> String {
    let (body, _) = detach(content);
    let value =
        serde_json::json!({ "title": title, "tags": tags, "favorite": favorite, "body": body });
    let mut bytes = Vec::new();
    canonical_json(&value, &mut bytes);
    let digest = Sha256::digest(&bytes);
    use std::fmt::Write;
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(hex, "{byte:02x}").expect("writing to String");
    }
    hex
}

fn canonical_json(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            output.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).expect("JSON key to memory");
                output.push(b':');
                canonical_json(&map[*key], output);
            }
            output.push(b'}');
        }
        Value::Array(values) => {
            output.push(b'[');
            for (i, v) in values.iter().enumerate() {
                if i != 0 {
                    output.push(b',');
                }
                canonical_json(v, output);
            }
            output.push(b']');
        }
        _ => serde_json::to_writer(output, value).expect("JSON value to memory"),
    }
}

pub fn mirror_item_id(seren_vault_id: Uuid, onepassword_item_id: &str) -> Uuid {
    Uuid::new_v5(
        &seren_vault_id,
        format!("1password:{onepassword_item_id}").as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::item::*;
    use serde_json::json;
    fn binding() -> SyncBinding {
        SyncBinding {
            source: "1password",
            account_id: "fixture-account".into(),
            vault_id: "fixture-vault".into(),
            item_id: "fixture-item".into(),
            item_version: 3,
            source_updated_at: "2026-10-16T00:00:00Z".into(),
            content_hash: "fixture-hash".into(),
            synced_at: "2026-10-17T00:00:00Z".into(),
        }
    }
    #[test]
    fn round_trip_all_bodies_preserves_metadata_and_hash_excludes_only_binding() {
        let bodies = [
            ItemContent::Login(Default::default()),
            ItemContent::SecureNote(Default::default()),
            ItemContent::ApiCredential(Default::default()),
            ItemContent::Card(Default::default()),
            ItemContent::Identity(Default::default()),
            ItemContent::Document(Default::default()),
            ItemContent::SshKey(Default::default()),
            ItemContent::Server(Default::default()),
            ItemContent::Database(Default::default()),
            ItemContent::BankAccount(Default::default()),
            ItemContent::Passport(Default::default()),
            ItemContent::DriverLicense(Default::default()),
            ItemContent::CryptoWallet(Default::default()),
        ];
        for body in bodies {
            for raw in [
                json!({}),
                json!({"source":{"password":"synthetic"},"other":null}),
            ] {
                let mut unbound = body.clone();
                *unbound.import_metadata_mut().0 = raw.into();
                let hash = content_hash("fixture", &[], false, &unbound);
                let mut bound = unbound.clone();
                attach(&mut bound, &binding()).unwrap();
                let (again, found) = detach(&bound);
                assert_eq!(again, unbound);
                assert_eq!(found, Some(binding()));
                assert_eq!(content_hash("fixture", &[], false, &bound), hash);
                assert_eq!(detach(&unbound), (unbound.clone(), None));
                assert_ne!(hash, content_hash("different", &[], false, &unbound));
                assert_ne!(
                    hash,
                    content_hash("fixture", &["tag".into()], false, &unbound)
                );
                assert_ne!(hash, content_hash("fixture", &[], true, &unbound));
            }
        }
    }
    #[test]
    fn non_object_attachment_is_refused_without_mutation() {
        for raw in [json!(null), json!(1), json!("synthetic-secret"), json!([])] {
            let mut item = ItemContent::Login(LoginContent {
                raw_import: raw.into(),
                ..Default::default()
            });
            let original = item.clone();
            assert_eq!(
                attach(&mut item, &binding()).unwrap_err().to_string(),
                "import error: sync binding requires object metadata"
            );
            assert_eq!(item, original);
            assert_eq!(detach(&item), (original, None));
        }
        let mut empty = ItemContent::Login(Default::default());
        let null_hash = content_hash("", &[], false, &empty);
        *empty.import_metadata_mut().0 = json!({}).into();
        assert_ne!(null_hash, content_hash("", &[], false, &empty));
    }
    #[test]
    fn strings_are_byte_exact_keys_are_utf16_sorted_and_numbers_use_crate_forms() {
        let a = ItemContent::Login(LoginContent {
            password: "é".into(),
            ..Default::default()
        });
        let b = ItemContent::Login(LoginContent {
            password: "e\u{301}".into(),
            ..Default::default()
        });
        assert_ne!(
            content_hash("", &[], false, &a),
            content_hash("", &[], false, &b)
        );
        let mut a = a;
        let mut b = a.clone();
        *a.import_metadata_mut().0 = serde_json::from_str::<Value>(r#"{"b":2,"a":{"z":1,"y":0}}"#)
            .unwrap()
            .into();
        *b.import_metadata_mut().0 = serde_json::from_str::<Value>(r#"{"a":{"y":0,"z":1},"b":2}"#)
            .unwrap()
            .into();
        assert_eq!(
            content_hash("", &[], false, &a),
            content_hash("", &[], false, &b)
        );
        let mut bytes = Vec::new();
        canonical_json(
            &json!({"\u{e000}":1,"\u{10000}":2,"a":[1.25," e\u{301} "]}),
            &mut bytes,
        );
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"a\":[1.25,\" e\u{301} \"],\"\u{10000}\":2,\"\u{e000}\":1}"
        );
    }
    #[test]
    fn item_identity_is_stable_and_vault_scoped() {
        let vault = Uuid::from_u128(1);
        let id = mirror_item_id(vault, "fixture-source");
        assert_eq!(id, mirror_item_id(vault, "fixture-source"));
        assert_eq!(id.get_version_num(), 5);
        assert_eq!(id.to_string(), "29450536-692f-576d-a41a-9c24e2c9dd1a");
        assert_ne!(id, mirror_item_id(Uuid::from_u128(2), "fixture-source"));
        assert_ne!(id, mirror_item_id(vault, "other-source"));
    }
}
