//! wasm-bindgen bindings for `seren-secrets-crypto`.
//!
//! Every exported function is a thin wrapper around the pure Rust
//! crate. Byte buffers cross the binding boundary as `&[u8]` or
//! `Vec<u8>`; errors are surfaced as `JsError`.
//!
//! The pure crate has zero wasm deps and is used unchanged by native
//! clients.
//!
//! Key handles are zeroized on free. Plaintext strings and generic byte buffers
//! are caller-owned after they cross the wasm-bindgen boundary.

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use seren_secrets_crypto::{
    aead,
    import::{
        ImportedItem, import_1pux as crate_import_1pux,
        import_bitwarden_encrypted_json as crate_import_bitwarden_encrypted_json,
        import_bitwarden_json as crate_import_bitwarden_json,
        import_keepass_xml as crate_import_keepass_xml,
    },
    kdf, kem,
    keys::{
        AccountKey, IdentityKemKeypair, IdentityKemPrivateKey, IdentityKemPublicKey,
        IdentitySigningKeypair, IdentitySigningPrivateKey, IdentitySigningPublicKey,
        ItemContentKey, RecoveryKey, VaultKey,
    },
    protocol::{
        account::{
            AccountSecrets, account_setup as crate_account_setup,
            account_setup_with_params as crate_account_setup_with_params,
            change_master_password as crate_change_master_password,
            unlock_account as crate_unlock_account,
            unwrap_account_signing_private_key as crate_unwrap_account_signing_private_key,
        },
        account_secrets_update::{
            AccountSecretsUpdateProof, build_update_proof, canonical_json_bytes,
            digest_account_secrets_blob,
        },
        agent_delegation_policy::{
            AgentDelegationContribution, agent_delegation_contribution_payload,
            sign_agent_delegation_contribution,
        },
        item::{
            ItemContent, decrypt_item_with_content_key as crate_decrypt_item_with_content_key,
            decrypt_metadata_json as crate_decrypt_metadata_json,
            decrypt_title as crate_decrypt_title,
            encrypt_item_with_content_key as crate_encrypt_item_with_content_key,
            encrypt_metadata_json as crate_encrypt_metadata_json,
            encrypt_title as crate_encrypt_title,
            generate_item_content_key as crate_generate_item_content_key,
            unwrap_item_content_key as crate_unwrap_item_content_key,
            wrap_item_content_key as crate_wrap_item_content_key,
        },
        recovery::{recover_with_recovery_key, rewrap_account_key_after_recovery},
        recovery_proof::{RecoveryProof, build_recovery_proof},
        vault::{
            decrypt_live_share_recipient_email as crate_decrypt_live_share_recipient_email,
            decrypt_vault_description as crate_decrypt_vault_description,
            decrypt_vault_invitation_email as crate_decrypt_vault_invitation_email,
            decrypt_vault_name as crate_decrypt_vault_name,
            encrypt_live_share_recipient_email as crate_encrypt_live_share_recipient_email,
            encrypt_vault_description as crate_encrypt_vault_description,
            encrypt_vault_invitation_email as crate_encrypt_vault_invitation_email,
            encrypt_vault_name as crate_encrypt_vault_name, generate_vault_key, unwrap_vault_key,
            wrap_vault_key_for_identity,
        },
    },
    signing,
};
use uuid::Uuid;

const X25519_KEY_LEN: usize = 32;
const ED25519_PUBLIC_LEN: usize = 32;
const ED25519_SECRET_LEN: usize = 32;

fn js_err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

fn secret_array<const N: usize>(
    bytes: &[u8],
    message: &'static str,
) -> Result<Zeroizing<[u8; N]>, JsError> {
    let raw: [u8; N] = bytes.try_into().map_err(|_| JsError::new(message))?;
    Ok(Zeroizing::new(raw))
}

fn item_kind(content: &ItemContent) -> &'static str {
    match content {
        ItemContent::Login(_) => "login",
        ItemContent::SecureNote(_) => "secure_note",
        ItemContent::ApiCredential(_) => "api_credential",
        ItemContent::Identity(_) => "identity",
        ItemContent::Card(_) => "card",
        ItemContent::SshKey(_) => "ssh_key",
        ItemContent::Document(_) => "document",
        ItemContent::BankAccount(_) => "bank_account",
        ItemContent::Passport(_) => "passport",
        ItemContent::DriverLicense(_) => "driver_license",
        ItemContent::CryptoWallet(_) => "crypto_wallet",
        ItemContent::Server(_) => "server",
        ItemContent::Database(_) => "database",
    }
}

fn imported_items_json(items: Vec<ImportedItem>) -> Result<String, JsError> {
    let encoded = items
        .into_iter()
        .map(|item| {
            let attachments = item
                .attachments
                .into_iter()
                .map(|attachment| {
                    serde_json::json!({
                        "id": attachment.id,
                        "filename": attachment.filename,
                        "content_type": attachment.content_type,
                        "size_bytes": attachment.data.len(),
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "title": item.title,
                "kind": item_kind(&item.content),
                "content": item.content,
                "favorite": item.favorite,
                "tags": item.tags,
                "source_collection": item.source_collection,
                "attachments": attachments,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&encoded).map_err(js_err)
}

#[wasm_bindgen]
pub struct WasmAccountKey {
    inner: AccountKey,
}

#[wasm_bindgen]
pub struct WasmKemPrivateKey {
    inner: IdentityKemPrivateKey,
}

#[wasm_bindgen]
pub struct WasmSigningPrivateKey {
    inner: IdentitySigningPrivateKey,
}

#[wasm_bindgen]
pub struct WasmRecoveryKey {
    inner: RecoveryKey,
}

#[wasm_bindgen]
pub struct WasmVaultKey {
    inner: VaultKey,
}

#[wasm_bindgen]
pub struct WasmItemContentKey {
    inner: ItemContentKey,
}

// ---------------------------------------------------------------------------
// KDF (Argon2id)
// ---------------------------------------------------------------------------

/// Default Argon2id parameters: 64 MiB memory, 2 iterations, 1 lane,
/// 32-byte output, 16-byte fresh random salt. The caller must persist the
/// salt and numeric parameters with the wrapped account secrets.
#[wasm_bindgen]
pub struct WasmKdfParams {
    inner: kdf::KdfParams,
}

#[wasm_bindgen]
impl WasmKdfParams {
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u8 {
        self.inner.version
    }
    #[wasm_bindgen(getter, js_name = "memoryKib")]
    pub fn memory_kib(&self) -> u32 {
        self.inner.memory_kib
    }
    #[wasm_bindgen(getter, js_name = "timeCost")]
    pub fn time_cost(&self) -> u32 {
        self.inner.time_cost
    }
    #[wasm_bindgen(getter)]
    pub fn parallelism(&self) -> u32 {
        self.inner.parallelism
    }
    #[wasm_bindgen(getter, js_name = "outputLen")]
    pub fn output_len(&self) -> u32 {
        self.inner.output_len
    }
    #[wasm_bindgen(getter)]
    pub fn salt(&self) -> Vec<u8> {
        self.inner.salt.clone()
    }
}

/// Mint a fresh set of default Argon2id parameters. The salt is
/// freshly random; the caller must persist the salt + the numeric
/// parameters as part of `account_secrets.kdf_params` so unlock can
/// replay the same derivation.
#[wasm_bindgen(js_name = "kdfDefaultParams")]
pub fn kdf_default_params() -> WasmKdfParams {
    WasmKdfParams {
        inner: kdf::default_params(),
    }
}

/// Mint the throughput probe profile (8 MiB / t=1). Run a single
/// `kdfDeriveKey` against this profile, measure the elapsed
/// milliseconds with `performance.now()`, and pass the result to
/// `kdfRecommendForThroughput` to pick the strongest profile this
/// host can derive inside the user's wall-clock budget.
#[wasm_bindgen(js_name = "kdfProbeParams")]
pub fn kdf_probe_params() -> WasmKdfParams {
    WasmKdfParams {
        inner: kdf::probe_params(),
    }
}

/// Pick a recommended profile given a measured probe time. `probe_ms`
/// is the wall-clock duration the caller observed running
/// `kdfDeriveKey(kdfProbeParams())`; `target_ms` is the time budget
/// the caller wants the eventual master-password derivation to fit
/// inside. Returns a profile with a fresh random salt that the caller
/// passes to `accountSetupWithParams`.
#[wasm_bindgen(js_name = "kdfRecommendForThroughput")]
pub fn kdf_recommend_for_throughput(probe_ms: u32, target_ms: u32) -> WasmKdfParams {
    WasmKdfParams {
        inner: kdf::recommend_params_for_throughput(u64::from(probe_ms), target_ms),
    }
}

/// Hard ceilings for the raw `kdfDeriveKey` binding. Parameters may be
/// server-supplied, so unbounded values must not reach the allocator.
/// Mirrors the backup-envelope caps in the core crate.
const KDF_MAX_MEMORY_KIB: u32 = 1024 * 1024;
const KDF_MAX_TIME_COST: u32 = 32;
const KDF_MAX_PARALLELISM: u32 = 64;
const KDF_MIN_MEMORY_KIB_PER_LANE: u32 = 8;
const KDF_MIN_OUTPUT_LEN: u32 = 16;
const KDF_MAX_OUTPUT_LEN: u32 = 64;
const KDF_MAX_SALT_LEN: usize = 1024;

/// Bounds check for the raw derive binding; plain Rust so it stays
/// testable on non-wasm targets.
fn check_kdf_derive_bounds(
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
    output_len: u32,
    salt_len: usize,
) -> Result<(), &'static str> {
    if parallelism == 0 || parallelism > KDF_MAX_PARALLELISM {
        return Err("kdf parallelism out of range");
    }
    if time_cost == 0 {
        return Err("kdf time_cost out of range");
    }
    let min_memory_kib = KDF_MIN_MEMORY_KIB_PER_LANE * parallelism;
    if memory_kib < min_memory_kib {
        return Err("kdf memory_kib too small");
    }
    if memory_kib > KDF_MAX_MEMORY_KIB {
        return Err("kdf memory_kib too large");
    }
    if time_cost > KDF_MAX_TIME_COST {
        return Err("kdf time_cost too large");
    }
    if !(KDF_MIN_OUTPUT_LEN..=KDF_MAX_OUTPUT_LEN).contains(&output_len) {
        return Err("kdf output_len out of range");
    }
    if salt_len > KDF_MAX_SALT_LEN {
        return Err("kdf salt too long");
    }
    Ok(())
}

/// Derive a key from a UTF-8 master password using Argon2id with the
/// supplied parameters. Throws on invalid parameters or oversized
/// output requests. For stored account profiles, validate with
/// `kdfValidateStoredParams` first; this raw helper only bounds resource
/// use, it does not enforce the approved profile set.
#[wasm_bindgen(js_name = "kdfDeriveKey")]
pub fn kdf_derive_key(
    password: &[u8],
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
    output_len: u32,
    salt: &[u8],
) -> Result<Vec<u8>, JsError> {
    check_kdf_derive_bounds(memory_kib, time_cost, parallelism, output_len, salt.len())
        .map_err(JsError::new)?;
    let params = kdf::KdfParams {
        version: 1,
        algorithm: kdf::KdfAlgorithm::Argon2id,
        memory_kib,
        time_cost,
        parallelism,
        output_len,
        salt: salt.to_vec(),
    };
    kdf::derive_key(password, &params).map_err(js_err)
}

/// Validate a stored Argon2id profile against the approved set this
/// crate can mint (the same gate `unlockAccount` applies). Use this
/// before deriving with server-supplied stored parameters outside the
/// high-level account flows. Throws when the profile is not approved.
#[wasm_bindgen(js_name = "kdfValidateStoredParams")]
pub fn kdf_validate_stored_params(
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
    output_len: u32,
    salt: &[u8],
) -> Result<(), JsError> {
    let params = kdf::KdfParams {
        version: 1,
        algorithm: kdf::KdfAlgorithm::Argon2id,
        memory_kib,
        time_cost,
        parallelism,
        output_len,
        salt: salt.to_vec(),
    };
    kdf::validate_stored_params(&params).map_err(js_err)
}

// ---------------------------------------------------------------------------
// AEAD (XChaCha20-Poly1305 envelope)
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with a 32-byte key. Output is a self-contained
/// envelope: `nonce || ciphertext || tag`.
#[wasm_bindgen(js_name = "aeadEncrypt")]
pub fn aead_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    let key = secret_array::<32>(key, "AEAD key must be 32 bytes")?;
    Ok(aead::xchacha20_encrypt(&key, plaintext))
}

/// Encrypt with additional authenticated data (AAD). The AAD is bound
/// into the tag but not included in the output. The decryptor must
/// supply the identical AAD bytes.
#[wasm_bindgen(js_name = "aeadEncryptWithAad")]
pub fn aead_encrypt_with_aad(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    let key = secret_array::<32>(key, "AEAD key must be 32 bytes")?;
    Ok(aead::xchacha20_encrypt_with_aad(&key, plaintext, aad))
}

/// Decrypt and authenticate an envelope produced by `aeadEncrypt`.
/// Throws when the tag does not verify under `key`.
#[wasm_bindgen(js_name = "aeadDecrypt")]
pub fn aead_decrypt(key: &[u8], blob: &[u8]) -> Result<Vec<u8>, JsError> {
    let key = secret_array::<32>(key, "AEAD key must be 32 bytes")?;
    aead::xchacha20_decrypt(&key, blob).map_err(js_err)
}

/// Decrypt with AAD; same as `aeadDecrypt` but the supplied AAD bytes
/// must match what the encryptor used or authentication fails.
#[wasm_bindgen(js_name = "aeadDecryptWithAad")]
pub fn aead_decrypt_with_aad(key: &[u8], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    let key = secret_array::<32>(key, "AEAD key must be 32 bytes")?;
    aead::xchacha20_decrypt_with_aad(&key, blob, aad).map_err(js_err)
}

#[wasm_bindgen(js_name = "vaultKeyAeadEncryptWithAad")]
pub fn vault_key_aead_encrypt_with_aad(
    vault_key: &WasmVaultKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    aead::xchacha20_encrypt_with_aad(vault_key.inner.as_bytes(), plaintext, aad)
}

#[wasm_bindgen(js_name = "vaultKeyAeadDecryptWithAad")]
pub fn vault_key_aead_decrypt_with_aad(
    vault_key: &WasmVaultKey,
    blob: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsError> {
    aead::xchacha20_decrypt_with_aad(vault_key.inner.as_bytes(), blob, aad).map_err(js_err)
}

// ---------------------------------------------------------------------------
// KEM (X25519 sealed box)
// ---------------------------------------------------------------------------

/// Identity KEM keypair. Public is 32 bytes (X25519 point), private is
/// 32 bytes (X25519 scalar). The private side is zeroized when this
/// struct is dropped, but getter-returned byte buffers are not.
/// Callers should drop those copies promptly.
#[wasm_bindgen]
pub struct WasmKemKeypair {
    inner: IdentityKemKeypair,
}

#[wasm_bindgen]
impl WasmKemKeypair {
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public.as_bytes().to_vec()
    }
    #[wasm_bindgen(getter, js_name = "privateKey")]
    pub fn private_key(&self) -> Vec<u8> {
        self.inner.private.as_bytes().to_vec()
    }
}

#[wasm_bindgen(js_name = "kemGenerateKeypair")]
pub fn kem_generate_keypair() -> WasmKemKeypair {
    WasmKemKeypair {
        inner: IdentityKemKeypair::generate(),
    }
}

/// Wrap `plaintext` for `recipient_public_key` (32-byte X25519 pubkey).
/// Output is `ephemeral_pubkey || nonce || ciphertext || tag`. The
/// recipient unwraps with their private key only; no signature, no
/// sender identity.
#[wasm_bindgen(js_name = "kemSeal")]
pub fn kem_seal(recipient_public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    let pk: [u8; X25519_KEY_LEN] = recipient_public_key
        .try_into()
        .map_err(|_| JsError::new("KEM public key must be 32 bytes"))?;
    let recipient = IdentityKemPublicKey(pk);
    Ok(kem::seal(&recipient, plaintext))
}

#[wasm_bindgen(js_name = "kemUnseal")]
pub fn kem_unseal(private_key: &[u8], blob: &[u8]) -> Result<Vec<u8>, JsError> {
    let sk = secret_array::<X25519_KEY_LEN>(private_key, "KEM private key must be 32 bytes")?;
    let private = IdentityKemPrivateKey::from_slice(&sk[..])
        .map_err(|_| JsError::new("Invalid KEM private key"))?;
    kem::unseal(&private, blob).map_err(js_err)
}

#[wasm_bindgen(js_name = "kemUnsealWithIdentityKey")]
pub fn kem_unseal_with_identity_key(
    private_key: &WasmKemPrivateKey,
    blob: &[u8],
) -> Result<Vec<u8>, JsError> {
    kem::unseal(&private_key.inner, blob).map_err(js_err)
}

// ---------------------------------------------------------------------------
// Signing (Ed25519)
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct WasmSigningKeypair {
    inner: IdentitySigningKeypair,
}

#[wasm_bindgen]
impl WasmSigningKeypair {
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public.as_bytes().to_vec()
    }
    #[wasm_bindgen(getter, js_name = "privateKey")]
    pub fn private_key(&self) -> Vec<u8> {
        self.inner.private.as_bytes().to_vec()
    }
}

#[wasm_bindgen(js_name = "signingGenerateKeypair")]
pub fn signing_generate_keypair() -> WasmSigningKeypair {
    WasmSigningKeypair {
        inner: IdentitySigningKeypair::generate(),
    }
}

#[wasm_bindgen(js_name = "sign")]
pub fn sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    let sk =
        secret_array::<ED25519_SECRET_LEN>(private_key, "Signing private key must be 32 bytes")?;
    let private = IdentitySigningPrivateKey::from_slice(&sk[..])
        .map_err(|_| JsError::new("Invalid signing private key"))?;
    Ok(signing::sign(&private, message))
}

#[wasm_bindgen(js_name = "verify")]
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk) = <[u8; ED25519_PUBLIC_LEN]>::try_from(public_key) else {
        return false;
    };
    let public = IdentitySigningPublicKey(pk);
    signing::verify(&public, message, signature).is_ok()
}

// ---------------------------------------------------------------------------
// Recovery key
// ---------------------------------------------------------------------------

/// Generate a 32-byte recovery key (CSPRNG). The caller renders this
/// for the user to write down at setup; it is also stored wrapped on
/// the server under `account_secrets.recovery_key_wrap` so account
/// recovery can recover the account key without the master password.
#[wasm_bindgen(js_name = "recoveryKeyGenerate")]
pub fn recovery_key_generate() -> WasmRecoveryKey {
    WasmRecoveryKey {
        inner: RecoveryKey::random(),
    }
}

/// Format a 32-byte recovery key for display: BASE32-NOPAD grouped
/// into 4-char chunks with hyphens. The user writes this down offline;
/// the same string parses back via `recoveryKeyParseDisplay`.
#[wasm_bindgen(js_name = "recoveryKeyToDisplay")]
pub fn recovery_key_to_display(key: &WasmRecoveryKey) -> String {
    key.inner.to_display_string()
}

#[wasm_bindgen(js_name = "recoveryKeyParseDisplay")]
pub fn recovery_key_parse_display(text: &str) -> Result<WasmRecoveryKey, JsError> {
    let key = RecoveryKey::from_display_string(text).map_err(js_err)?;
    Ok(WasmRecoveryKey { inner: key })
}

// ---------------------------------------------------------------------------
// Smoke test exposed so the wrapper can verify the WASM binary
// actually loaded and the random source works.
// ---------------------------------------------------------------------------

/// Round-trip self-test: generate a KEM keypair, seal a small payload
/// to it, unseal it, and return the recovered plaintext. Throws if any
/// step fails. Call this on init so callers can fail closed on a
/// partially-loaded WASM binary.
#[wasm_bindgen(js_name = "selfTest")]
pub fn self_test() -> Result<Vec<u8>, JsError> {
    let kp = IdentityKemKeypair::generate();
    let payload = b"seren-secrets-crypto-wasm self test";
    let sealed = kem::seal(&kp.public, payload);
    let opened = kem::unseal(&kp.private, &sealed).map_err(js_err)?;
    if opened != payload {
        return Err(JsError::new("self-test round-trip mismatch"));
    }
    Ok(opened)
}

// ---------------------------------------------------------------------------
// Foreign password-manager imports
// ---------------------------------------------------------------------------

/// Decode a 1Password `.1pux` archive into normalized plaintext items.
///
/// The returned JSON is a transfer format. The caller
/// must encrypt every returned item before POSTing to the server.
#[wasm_bindgen(js_name = "importOnePassword1pux")]
pub fn import_one_password_1pux(archive_bytes: &[u8]) -> Result<String, JsError> {
    imported_items_json(crate_import_1pux(archive_bytes).map_err(js_err)?)
}

/// Decode a Bitwarden encrypted JSON export into normalized plaintext items.
///
/// The master password is never sent to the server.
#[wasm_bindgen(js_name = "importBitwardenEncryptedJson")]
pub fn import_bitwarden_encrypted_json(
    export_json: &[u8],
    master_password: &[u8],
) -> Result<String, JsError> {
    imported_items_json(
        crate_import_bitwarden_encrypted_json(export_json, master_password).map_err(js_err)?,
    )
}

/// Decode a Bitwarden unencrypted JSON export into normalized plaintext items.
#[wasm_bindgen(js_name = "importBitwardenJson")]
pub fn import_bitwarden_json(export_json: &[u8]) -> Result<String, JsError> {
    imported_items_json(crate_import_bitwarden_json(export_json).map_err(js_err)?)
}

/// Decode a KeePass XML database export into normalized plaintext items.
#[wasm_bindgen(js_name = "importKeepassXml")]
pub fn import_keepass_xml(export_xml: &[u8]) -> Result<String, JsError> {
    imported_items_json(crate_import_keepass_xml(export_xml).map_err(js_err)?)
}

// ---------------------------------------------------------------------------
// High-level account flows
// ---------------------------------------------------------------------------

/// Bundle produced by first-run setup.
#[wasm_bindgen]
pub struct WasmAccountSetupBundle {
    secrets: AccountSecrets,
    recovery_key: RecoveryKey,
}

#[wasm_bindgen]
impl WasmAccountSetupBundle {
    /// JSON-encoded `AccountSecrets` blob.
    #[wasm_bindgen(getter, js_name = "secretsJson")]
    pub fn secrets_json(&self) -> Result<String, JsError> {
        serde_json::to_string(&self.secrets).map_err(js_err)
    }

    #[wasm_bindgen(getter, js_name = "kemPublicKey")]
    pub fn kem_public_key(&self) -> Vec<u8> {
        self.secrets.kem_public_key.as_bytes().to_vec()
    }

    #[wasm_bindgen(getter, js_name = "signingPublicKey")]
    pub fn signing_public_key(&self) -> Vec<u8> {
        self.secrets.signing_public_key.as_bytes().to_vec()
    }

    #[wasm_bindgen(getter, js_name = "recoveryKeyDisplay")]
    pub fn recovery_key_display(&self) -> String {
        self.recovery_key.to_display_string()
    }
}

/// Run first-time account setup with the built-in default Argon2id
/// profile (64 MiB / t=2). Use `accountSetupWithParams` when the
/// caller has probed the host's KDF throughput and wants a
/// downgraded profile so unlock fits inside the user's wall-clock
/// budget on weaker devices.
#[wasm_bindgen(js_name = "accountSetup")]
pub fn account_setup(master_password: &[u8]) -> Result<WasmAccountSetupBundle, JsError> {
    let bundle = crate_account_setup(master_password).map_err(js_err)?;
    Ok(WasmAccountSetupBundle {
        secrets: bundle.secrets,
        recovery_key: bundle.recovery_key,
    })
}

/// Run first-time account setup using caller-supplied Argon2id
/// profiles. Pair this with `kdfProbeParams` +
/// `kdfRecommendForThroughput` to pick a profile inside the unlock budget.
#[wasm_bindgen(js_name = "accountSetupWithParams")]
pub fn account_setup_with_params(
    master_password: &[u8],
    master_params: &WasmKdfParams,
    recovery_params: &WasmKdfParams,
) -> Result<WasmAccountSetupBundle, JsError> {
    let bundle = crate_account_setup_with_params(
        master_password,
        master_params.inner.clone(),
        recovery_params.inner.clone(),
    )
    .map_err(js_err)?;
    Ok(WasmAccountSetupBundle {
        secrets: bundle.secrets,
        recovery_key: bundle.recovery_key,
    })
}

/// Material returned by a successful unlock.
#[wasm_bindgen]
pub struct WasmUnlockedAccount {
    account_key: AccountKey,
    kem_private: IdentityKemPrivateKey,
    signing_private: IdentitySigningPrivateKey,
}

#[wasm_bindgen]
impl WasmUnlockedAccount {
    #[wasm_bindgen(getter, js_name = "accountKey")]
    pub fn account_key(&self) -> WasmAccountKey {
        WasmAccountKey {
            inner: self.account_key.clone(),
        }
    }
    #[wasm_bindgen(getter, js_name = "kemPrivateKey")]
    pub fn kem_private_key(&self) -> WasmKemPrivateKey {
        WasmKemPrivateKey {
            inner: self.kem_private.clone(),
        }
    }
    #[wasm_bindgen(getter, js_name = "signingPrivateKey")]
    pub fn signing_private_key(&self) -> WasmSigningPrivateKey {
        WasmSigningPrivateKey {
            inner: self.signing_private.clone(),
        }
    }
}

/// Derive the master key from `master_password` using the kdf params
/// inside the supplied `account_secrets` JSON blob, then unwrap the
/// account key and the identity private keys. Throws on a bad
/// password (the AEAD tag won't verify) or on a malformed blob.
#[wasm_bindgen(js_name = "unlockAccount")]
pub fn unlock_account(
    master_password: &[u8],
    secrets_json: &str,
) -> Result<WasmUnlockedAccount, JsError> {
    let secrets: AccountSecrets = serde_json::from_str(secrets_json)
        .map_err(|_| JsError::new("invalid account secrets JSON"))?;
    let unlocked = crate_unlock_account(master_password, &secrets).map_err(js_err)?;
    Ok(WasmUnlockedAccount {
        account_key: unlocked.account_key,
        kem_private: unlocked.kem_private,
        signing_private: unlocked.signing_private,
    })
}

/// Recover the account key using the recovery key.
#[wasm_bindgen(js_name = "recoverAccountKey")]
pub fn recover_account_key(
    recovery_key: &WasmRecoveryKey,
    secrets_json: &str,
) -> Result<WasmAccountKey, JsError> {
    let secrets: AccountSecrets = serde_json::from_str(secrets_json)
        .map_err(|_| JsError::new("invalid account secrets JSON"))?;
    let account_key = recover_with_recovery_key(&recovery_key.inner, &secrets).map_err(js_err)?;
    Ok(WasmAccountKey { inner: account_key })
}

#[wasm_bindgen(js_name = "accountSigningPrivateUnwrap")]
pub fn account_signing_private_unwrap(
    account_key: &WasmAccountKey,
    account_signing_private_wrap: &[u8],
) -> Result<WasmSigningPrivateKey, JsError> {
    let signing_private =
        crate_unwrap_account_signing_private_key(&account_key.inner, account_signing_private_wrap)
            .map_err(js_err)?;
    Ok(WasmSigningPrivateKey {
        inner: signing_private,
    })
}

/// Result of rewrapping the account secrets blob after a successful
/// recovery. `newSecretsJson` is the complete `AccountSecrets` JSON
/// the caller posts to `PUT /account/recovery/complete` (after picking
/// the fields out into `RecoveryNewAccountSecrets`).
#[wasm_bindgen]
pub struct WasmRecoveryRewrap {
    secrets_json: Zeroizing<String>,
    new_recovery_key: RecoveryKey,
}

#[wasm_bindgen]
impl WasmRecoveryRewrap {
    #[wasm_bindgen(getter, js_name = "newSecretsJson")]
    pub fn new_secrets_json(&self) -> String {
        self.secrets_json.as_str().to_owned()
    }

    #[wasm_bindgen(getter, js_name = "newRecoveryKey")]
    pub fn new_recovery_key(&self) -> WasmRecoveryKey {
        WasmRecoveryKey {
            inner: self.new_recovery_key.clone(),
        }
    }

    #[wasm_bindgen(getter, js_name = "newRecoveryKeyDisplay")]
    pub fn new_recovery_key_display(&self) -> String {
        self.new_recovery_key.to_display_string()
    }
}

/// Re-wrap the account_key under a fresh master-password-derived key
/// and rotate the recovery key. The caller supplies the account key
/// recovered via `recoverAccountKey` along with the existing secrets
/// blob; the returned bundle contains the updated `AccountSecrets`
/// JSON and the new recovery key handle plus display string.
#[wasm_bindgen(js_name = "rewrapAccountAfterRecovery")]
pub fn rewrap_account_after_recovery(
    account_key: &WasmAccountKey,
    new_password: &[u8],
    secrets_json: &str,
) -> Result<WasmRecoveryRewrap, JsError> {
    let mut secrets: AccountSecrets = serde_json::from_str(secrets_json)
        .map_err(|_| JsError::new("invalid account secrets JSON"))?;
    let new_recovery_key =
        rewrap_account_key_after_recovery(&account_key.inner, new_password, &mut secrets)
            .map_err(js_err)?;
    let updated = serde_json::to_string(&secrets).map_err(js_err)?;
    Ok(WasmRecoveryRewrap {
        secrets_json: Zeroizing::new(updated),
        new_recovery_key,
    })
}

/// Sign the canonical recovery-proof bytes with the recovered
/// identity signing private key. The server's `/account/recovery/
/// complete` verifies this signature against the existing signing
/// public key it has on file.
#[wasm_bindgen(js_name = "signRecoveryProof")]
pub fn sign_recovery_proof(
    signing_private_key: &WasmSigningPrivateKey,
    recovery_request_id: &[u8],
    user_id: &[u8],
    challenge: &[u8],
    new_kem_public_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    let request_bytes: [u8; 16] = recovery_request_id
        .try_into()
        .map_err(|_| JsError::new("recovery_request_id must be 16 bytes"))?;
    let user_bytes: [u8; 16] = user_id
        .try_into()
        .map_err(|_| JsError::new("user_id must be 16 bytes"))?;
    let challenge_bytes: [u8; 32] = challenge
        .try_into()
        .map_err(|_| JsError::new("challenge must be 32 bytes"))?;
    let kem_pk_bytes: [u8; X25519_KEY_LEN] = new_kem_public_key
        .try_into()
        .map_err(|_| JsError::new("new_kem_public_key must be 32 bytes"))?;

    let proof = RecoveryProof {
        recovery_request_id: Uuid::from_bytes(request_bytes),
        user_id: Uuid::from_bytes(user_bytes),
        challenge: challenge_bytes,
        new_kem_public_key: IdentityKemPublicKey(kem_pk_bytes),
    };
    Ok(build_recovery_proof(&signing_private_key.inner, &proof))
}

/// Re-wrap the account_key under a fresh master-password-derived
/// key without rotating the recovery key. Used by the settings-page
/// change-master-password flow: the recovery sheet keeps working
/// because only the master-password wrap changes.
#[wasm_bindgen(js_name = "changeMasterPassword")]
pub fn change_master_password(
    account_key: &WasmAccountKey,
    new_password: &[u8],
    secrets_json: &str,
) -> Result<String, JsError> {
    let mut secrets: AccountSecrets = serde_json::from_str(secrets_json)
        .map_err(|_| JsError::new("invalid account secrets JSON"))?;
    crate_change_master_password(&account_key.inner, new_password, &mut secrets).map_err(js_err)?;
    serde_json::to_string(&secrets).map_err(js_err)
}

/// Sign the account-secrets update proof.
///
/// KDF JSON inputs are parsed and canonicalized before hashing.
#[wasm_bindgen(js_name = "signSecretsUpdateProof")]
#[allow(clippy::too_many_arguments)]
pub fn sign_secrets_update_proof(
    signing_private_key: &WasmSigningPrivateKey,
    user_id: &[u8],
    issued_at_rfc3339: &str,
    kdf_params_json: &str,
    recovery_kdf_params_json: &str,
    account_key_wrap: &[u8],
    account_kem_private_wrap: &[u8],
    account_signing_private_wrap: &[u8],
    recovery_key_wrap: &[u8],
) -> Result<Vec<u8>, JsError> {
    let user_bytes: [u8; 16] = user_id
        .try_into()
        .map_err(|_| JsError::new("user_id must be 16 bytes"))?;

    let issued_at = issued_at_rfc3339
        .parse::<jiff::Timestamp>()
        .map_err(|e| JsError::new(&format!("Invalid issued_at: {e}")))?;

    let kdf_value: serde_json::Value = serde_json::from_str(kdf_params_json)
        .map_err(|_| JsError::new("invalid kdf params JSON"))?;
    let recovery_kdf_value: serde_json::Value = serde_json::from_str(recovery_kdf_params_json)
        .map_err(|_| JsError::new("invalid recovery kdf params JSON"))?;
    let kdf_bytes = canonical_json_bytes(&kdf_value).map_err(js_err)?;
    let recovery_kdf_bytes = canonical_json_bytes(&recovery_kdf_value).map_err(js_err)?;

    let blob_digest = digest_account_secrets_blob(
        &kdf_bytes,
        &recovery_kdf_bytes,
        account_key_wrap,
        account_kem_private_wrap,
        account_signing_private_wrap,
        recovery_key_wrap,
    );

    let proof = AccountSecretsUpdateProof {
        user_id: Uuid::from_bytes(user_bytes),
        issued_at,
        blob_digest,
    };
    Ok(build_update_proof(&signing_private_key.inner, &proof))
}

// ---------------------------------------------------------------------------
// Vault key management
// ---------------------------------------------------------------------------

/// Generate a fresh vault key. Transmit only per-identity sealed wraps.
#[wasm_bindgen(js_name = "vaultKeyGenerate")]
pub fn vault_key_generate() -> WasmVaultKey {
    WasmVaultKey {
        inner: generate_vault_key(),
    }
}

/// Wrap a vault key for the given identity KEM public key.
#[wasm_bindgen(js_name = "vaultKeyWrapForIdentity")]
pub fn vault_key_wrap_for_identity(
    vault_key: &WasmVaultKey,
    recipient_public_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    let pk_bytes: [u8; X25519_KEY_LEN] = recipient_public_key
        .try_into()
        .map_err(|_| JsError::new("Recipient KEM public key must be 32 bytes"))?;
    let recipient = IdentityKemPublicKey(pk_bytes);
    Ok(wrap_vault_key_for_identity(&vault_key.inner, &recipient))
}

/// Unwrap a vault key previously wrapped by `vaultKeyWrapForIdentity`.
#[wasm_bindgen(js_name = "vaultKeyUnwrap")]
pub fn vault_key_unwrap(
    kem_private_key: &WasmKemPrivateKey,
    wrapped_vault_key: &[u8],
) -> Result<WasmVaultKey, JsError> {
    let key = unwrap_vault_key(&kem_private_key.inner, wrapped_vault_key).map_err(js_err)?;
    Ok(WasmVaultKey { inner: key })
}

#[wasm_bindgen(js_name = "vaultNameEncrypt")]
pub fn vault_name_encrypt(
    vault_key: &WasmVaultKey,
    vault_id: &[u8],
    name: &str,
) -> Result<Vec<u8>, JsError> {
    if vault_id.len() != 16 {
        return Err(JsError::new("vault_id must be 16 bytes (UUID)"));
    }
    Ok(crate_encrypt_vault_name(&vault_key.inner, vault_id, name))
}

#[wasm_bindgen(js_name = "vaultNameDecrypt")]
pub fn vault_name_decrypt(
    vault_key: &WasmVaultKey,
    vault_id: &[u8],
    blob: &[u8],
) -> Result<String, JsError> {
    if vault_id.len() != 16 {
        return Err(JsError::new("vault_id must be 16 bytes (UUID)"));
    }
    crate_decrypt_vault_name(&vault_key.inner, vault_id, blob).map_err(js_err)
}

#[wasm_bindgen(js_name = "vaultDescriptionEncrypt")]
pub fn vault_description_encrypt(
    vault_key: &WasmVaultKey,
    vault_id: &[u8],
    description: &str,
) -> Result<Vec<u8>, JsError> {
    if vault_id.len() != 16 {
        return Err(JsError::new("vault_id must be 16 bytes (UUID)"));
    }
    Ok(crate_encrypt_vault_description(
        &vault_key.inner,
        vault_id,
        description,
    ))
}

#[wasm_bindgen(js_name = "vaultDescriptionDecrypt")]
pub fn vault_description_decrypt(
    vault_key: &WasmVaultKey,
    vault_id: &[u8],
    blob: &[u8],
) -> Result<String, JsError> {
    if vault_id.len() != 16 {
        return Err(JsError::new("vault_id must be 16 bytes (UUID)"));
    }
    crate_decrypt_vault_description(&vault_key.inner, vault_id, blob).map_err(js_err)
}

#[wasm_bindgen(js_name = "vaultInvitationEmailEncrypt")]
pub fn vault_invitation_email_encrypt(
    vault_key: &WasmVaultKey,
    vault_id: &[u8],
    invitation_id: &[u8],
    email: &str,
) -> Result<Vec<u8>, JsError> {
    if vault_id.len() != 16 {
        return Err(JsError::new("vault_id must be 16 bytes (UUID)"));
    }
    if invitation_id.len() != 16 {
        return Err(JsError::new("invitation_id must be 16 bytes (UUID)"));
    }
    Ok(crate_encrypt_vault_invitation_email(
        &vault_key.inner,
        vault_id,
        invitation_id,
        email,
    ))
}

#[wasm_bindgen(js_name = "vaultInvitationEmailDecrypt")]
pub fn vault_invitation_email_decrypt(
    vault_key: &WasmVaultKey,
    vault_id: &[u8],
    invitation_id: &[u8],
    blob: &[u8],
) -> Result<String, JsError> {
    if vault_id.len() != 16 {
        return Err(JsError::new("vault_id must be 16 bytes (UUID)"));
    }
    if invitation_id.len() != 16 {
        return Err(JsError::new("invitation_id must be 16 bytes (UUID)"));
    }
    crate_decrypt_vault_invitation_email(&vault_key.inner, vault_id, invitation_id, blob)
        .map_err(js_err)
}

#[wasm_bindgen(js_name = "liveShareRecipientEmailEncrypt")]
pub fn live_share_recipient_email_encrypt(
    vault_key: &WasmVaultKey,
    vault_id: &[u8],
    share_id: &[u8],
    email: &str,
) -> Result<Vec<u8>, JsError> {
    if vault_id.len() != 16 {
        return Err(JsError::new("vault_id must be 16 bytes (UUID)"));
    }
    if share_id.len() != 16 {
        return Err(JsError::new("share_id must be 16 bytes (UUID)"));
    }
    Ok(crate_encrypt_live_share_recipient_email(
        &vault_key.inner,
        vault_id,
        share_id,
        email,
    ))
}

#[wasm_bindgen(js_name = "liveShareRecipientEmailDecrypt")]
pub fn live_share_recipient_email_decrypt(
    vault_key: &WasmVaultKey,
    vault_id: &[u8],
    share_id: &[u8],
    blob: &[u8],
) -> Result<String, JsError> {
    if vault_id.len() != 16 {
        return Err(JsError::new("vault_id must be 16 bytes (UUID)"));
    }
    if share_id.len() != 16 {
        return Err(JsError::new("share_id must be 16 bytes (UUID)"));
    }
    crate_decrypt_live_share_recipient_email(&vault_key.inner, vault_id, share_id, blob)
        .map_err(js_err)
}

// ---------------------------------------------------------------------------
// Agent and membership grant signatures
// ---------------------------------------------------------------------------

fn canonical_create_agent_bytes(
    display_name: &str,
    kem_public_key: &[u8; X25519_KEY_LEN],
    signing_public_key: &[u8; ED25519_PUBLIC_LEN],
    key_provenance: &serde_json::Value,
    issued_at: i64,
    nonce: &str,
) -> Result<Vec<u8>, JsError> {
    let canonical = serde_json::json!({
        "display_name": display_name,
        "kem_public_key": B64.encode(kem_public_key),
        "signing_public_key": B64.encode(signing_public_key),
        "key_provenance": key_provenance,
        // Hosted agents sign kms_key_id as null; the backend verifies the same bytes.
        "kms_key_id": serde_json::Value::Null,
        "issued_at": issued_at,
        "nonce": nonce,
    });
    serde_json::to_vec(&canonical).map_err(js_err)
}

/// Sign a create-agent request with the account signing private key.
#[wasm_bindgen(js_name = "createAgentSign")]
pub fn create_agent_sign(
    signing_private_key: &WasmSigningPrivateKey,
    display_name: &str,
    kem_public_key: &[u8],
    agent_signing_public_key: &[u8],
    key_provenance_json: &str,
    issued_at: i64,
    nonce: &str,
) -> Result<Vec<u8>, JsError> {
    let kem_public_key: [u8; X25519_KEY_LEN] = kem_public_key
        .try_into()
        .map_err(|_| JsError::new("kem_public_key must be 32 bytes"))?;
    let agent_signing_public_key: [u8; ED25519_PUBLIC_LEN] = agent_signing_public_key
        .try_into()
        .map_err(|_| JsError::new("signing_public_key must be 32 bytes"))?;
    let key_provenance: serde_json::Value = serde_json::from_str(key_provenance_json)
        .map_err(|_| JsError::new("invalid key provenance JSON"))?;
    let canonical = canonical_create_agent_bytes(
        display_name,
        &kem_public_key,
        &agent_signing_public_key,
        &key_provenance,
        issued_at,
        nonce,
    )?;
    Ok(signing::sign(&signing_private_key.inner, &canonical))
}

/// Sign an ensure-hosted-agent request with the account signing private key.
/// Hosted identities have no client-provided public keys, so their canonical
/// payload is intentionally distinct from the create-agent payload above.
#[wasm_bindgen(js_name = "hostedAgentSign")]
pub fn hosted_agent_sign(
    signing_private_key: &WasmSigningPrivateKey,
    display_name: &str,
    key_provenance_json: &str,
    issued_at: i64,
    nonce: &str,
) -> Result<Vec<u8>, JsError> {
    let key_provenance: serde_json::Value = serde_json::from_str(key_provenance_json)
        .map_err(|_| JsError::new("invalid key provenance JSON"))?;
    let canonical = serde_json::json!({
        "display_name": display_name,
        "key_provenance": key_provenance,
        "issued_at": issued_at,
        "nonce": nonce,
    });
    let canonical = serde_json::to_vec(&canonical).map_err(js_err)?;
    Ok(signing::sign(&signing_private_key.inner, &canonical))
}

/// Sign a vault membership grant. The access-level byte is fixed protocol
/// data; the canonical byte layout lives in
/// `seren_secrets_crypto::protocol::membership_grant`.
#[wasm_bindgen(js_name = "membershipGrantSign")]
pub fn membership_grant_sign(
    signing_private_key: &WasmSigningPrivateKey,
    vault_id: &[u8],
    identity_id: &[u8],
    access_level: u8,
    wrapped_vault_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    let vault_id: [u8; 16] = vault_id
        .try_into()
        .map_err(|_| JsError::new("vault_id must be 16 bytes (UUID)"))?;
    let identity_id: [u8; 16] = identity_id
        .try_into()
        .map_err(|_| JsError::new("identity_id must be 16 bytes (UUID)"))?;
    Ok(
        seren_secrets_crypto::protocol::membership_grant::sign_membership_grant(
            &signing_private_key.inner,
            &vault_id,
            &identity_id,
            access_level,
            wrapped_vault_key,
        ),
    )
}

/// Build the canonical bytes for a multi-principal agent delegation
/// contribution. The input is a JSON-encoded `AgentDelegationContribution`;
/// the domain separator is inserted by the shared Rust implementation rather
/// than accepted from the caller.
#[wasm_bindgen(js_name = "agentDelegationContributionPayload")]
pub fn agent_delegation_contribution_payload_wasm(
    contribution_json: &str,
) -> Result<Vec<u8>, JsError> {
    if contribution_json.len() > 2 * 1024 * 1024 {
        return Err(JsError::new("delegation contribution JSON is too large"));
    }
    let contribution: AgentDelegationContribution = serde_json::from_str(contribution_json)
        .map_err(|_| JsError::new("invalid delegation contribution JSON"))?;
    agent_delegation_contribution_payload(contribution).map_err(js_err)
}

/// Canonicalize and sign a multi-principal agent-delegation contribution with
/// the live identity signing key.
#[wasm_bindgen(js_name = "agentDelegationContributionSign")]
pub fn agent_delegation_contribution_sign_wasm(
    signing_private_key: &WasmSigningPrivateKey,
    contribution_json: &str,
) -> Result<Vec<u8>, JsError> {
    if contribution_json.len() > 2 * 1024 * 1024 {
        return Err(JsError::new("delegation contribution JSON is too large"));
    }
    let contribution: AgentDelegationContribution = serde_json::from_str(contribution_json)
        .map_err(|_| JsError::new("invalid delegation contribution JSON"))?;
    sign_agent_delegation_contribution(&signing_private_key.inner, contribution).map_err(js_err)
}

// ---------------------------------------------------------------------------
// Item title / body
// ---------------------------------------------------------------------------

/// Encrypt an item title under the given vault key. Title AAD is
/// `b"title:" || item_id_bytes(16)` so the ciphertext is bound to a
/// specific item and cannot be moved to another row server-side.
#[wasm_bindgen(js_name = "itemTitleEncrypt")]
pub fn item_title_encrypt(
    vault_key: &WasmVaultKey,
    item_id: &[u8],
    title: &str,
) -> Result<Vec<u8>, JsError> {
    if item_id.len() != 16 {
        return Err(JsError::new("item_id must be 16 bytes (UUID)"));
    }
    Ok(crate_encrypt_title(&vault_key.inner, item_id, title))
}

#[wasm_bindgen(js_name = "itemTitleDecrypt")]
pub fn item_title_decrypt(
    vault_key: &WasmVaultKey,
    item_id: &[u8],
    blob: &[u8],
) -> Result<String, JsError> {
    if item_id.len() != 16 {
        return Err(JsError::new("item_id must be 16 bytes (UUID)"));
    }
    crate_decrypt_title(&vault_key.inner, item_id, blob).map_err(js_err)
}

/// Encrypt the tags vector under the vault key with AAD bound to the
/// item id. `tags_json` must be a JSON-encoded `Vec<String>`. Output
/// is the bytes the caller persists as `tags_ciphertext`.
#[wasm_bindgen(js_name = "itemTagsEncrypt")]
pub fn item_tags_encrypt(
    vault_key: &WasmVaultKey,
    item_id: &[u8],
    tags_json: &str,
) -> Result<Vec<u8>, JsError> {
    if item_id.len() != 16 {
        return Err(JsError::new("item_id must be 16 bytes (UUID)"));
    }
    let tags: Vec<String> =
        serde_json::from_str(tags_json).map_err(|_| JsError::new("invalid tags JSON"))?;
    seren_secrets_crypto::protocol::item::encrypt_tags(&vault_key.inner, item_id, &tags)
        .map_err(js_err)
}

/// Decrypt a `tags_ciphertext` blob into the canonical JSON shape
/// (a JSON-encoded `Vec<String>`). Used by the items list to surface
/// tags for filter / search without round-tripping through the body
/// AEAD decrypt.
#[wasm_bindgen(js_name = "itemTagsDecrypt")]
pub fn item_tags_decrypt(
    vault_key: &WasmVaultKey,
    item_id: &[u8],
    blob: &[u8],
) -> Result<String, JsError> {
    if item_id.len() != 16 {
        return Err(JsError::new("item_id must be 16 bytes (UUID)"));
    }
    let tags = seren_secrets_crypto::protocol::item::decrypt_tags(&vault_key.inner, item_id, blob)
        .map_err(js_err)?;
    serde_json::to_string(&tags).map_err(js_err)
}

#[wasm_bindgen(js_name = "itemMetadataEncrypt")]
pub fn item_metadata_encrypt(
    vault_key: &WasmVaultKey,
    item_id: &[u8],
    metadata_json: &str,
) -> Result<Vec<u8>, JsError> {
    if item_id.len() != 16 {
        return Err(JsError::new("item_id must be 16 bytes (UUID)"));
    }
    serde_json::from_str::<serde_json::Value>(metadata_json)
        .map_err(|_| JsError::new("invalid metadata JSON"))?;
    Ok(crate_encrypt_metadata_json(
        &vault_key.inner,
        item_id,
        metadata_json,
    ))
}

#[wasm_bindgen(js_name = "itemMetadataDecrypt")]
pub fn item_metadata_decrypt(
    vault_key: &WasmVaultKey,
    item_id: &[u8],
    blob: &[u8],
) -> Result<String, JsError> {
    if item_id.len() != 16 {
        return Err(JsError::new("item_id must be 16 bytes (UUID)"));
    }
    crate_decrypt_metadata_json(&vault_key.inner, item_id, blob).map_err(js_err)
}

// ---------------------------------------------------------------------------
// Per-item content keys
//
// Items use a fresh per-item content key. The content key is wrapped under
// the vault key (so every vault member can derive it on read) and the body
// is encrypted under that content key (so a single content key can be
// handed off to an approver or share recipient without disclosing the
// rest of the vault).

/// Generate a fresh item content key.
#[wasm_bindgen(js_name = "itemContentKeyGenerate")]
pub fn item_content_key_generate() -> WasmItemContentKey {
    WasmItemContentKey {
        inner: crate_generate_item_content_key(),
    }
}

/// Seal a content key under the vault key with item-id AAD.
#[wasm_bindgen(js_name = "itemContentKeyWrap")]
pub fn item_content_key_wrap(
    vault_key: &WasmVaultKey,
    item_id: &[u8],
    content_key: &WasmItemContentKey,
) -> Result<Vec<u8>, JsError> {
    if item_id.len() != 16 {
        return Err(JsError::new("item_id must be 16 bytes (UUID)"));
    }
    Ok(crate_wrap_item_content_key(
        &vault_key.inner,
        item_id,
        &content_key.inner,
    ))
}

/// Unseal a content key from the vault-key wrap on the item row.
#[wasm_bindgen(js_name = "itemContentKeyUnwrap")]
pub fn item_content_key_unwrap(
    vault_key: &WasmVaultKey,
    item_id: &[u8],
    blob: &[u8],
) -> Result<WasmItemContentKey, JsError> {
    if item_id.len() != 16 {
        return Err(JsError::new("item_id must be 16 bytes (UUID)"));
    }
    let ck = crate_unwrap_item_content_key(&vault_key.inner, item_id, blob).map_err(js_err)?;
    Ok(WasmItemContentKey { inner: ck })
}

/// Wrap a content key for the given identity KEM public key.
#[wasm_bindgen(js_name = "itemContentKeyWrapForIdentity")]
pub fn item_content_key_wrap_for_identity(
    content_key: &WasmItemContentKey,
    recipient_public_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    let pk_bytes: [u8; X25519_KEY_LEN] = recipient_public_key
        .try_into()
        .map_err(|_| JsError::new("Recipient KEM public key must be 32 bytes"))?;
    let recipient = IdentityKemPublicKey(pk_bytes);
    Ok(kem::seal(&recipient, content_key.inner.as_bytes()))
}

/// Unwrap a content key previously wrapped by `itemContentKeyWrapForIdentity`.
#[wasm_bindgen(js_name = "itemContentKeyUnwrapForIdentity")]
pub fn item_content_key_unwrap_for_identity(
    kem_private_key: &WasmKemPrivateKey,
    wrapped_content_key: &[u8],
) -> Result<WasmItemContentKey, JsError> {
    let bytes =
        Zeroizing::new(kem::unseal(&kem_private_key.inner, wrapped_content_key).map_err(js_err)?);
    let raw = Zeroizing::new(
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| JsError::new("Content key must be 32 bytes"))?,
    );
    Ok(WasmItemContentKey {
        inner: ItemContentKey::from_bytes(*raw),
    })
}

/// Encrypt an item body under its per-item content key. Mirrors
/// `itemBodyEncrypt` but reads the key from the content-key envelope
/// rather than directly from the vault key.
#[wasm_bindgen(js_name = "itemBodyEncryptWithContentKey")]
pub fn item_body_encrypt_with_content_key(
    content_key: &WasmItemContentKey,
    item_id: &[u8],
    content_json: &str,
) -> Result<Vec<u8>, JsError> {
    if item_id.len() != 16 {
        return Err(JsError::new("item_id must be 16 bytes (UUID)"));
    }
    let content: ItemContent = serde_json::from_str(content_json)
        .map_err(|_| JsError::new("invalid item content JSON"))?;
    crate_encrypt_item_with_content_key(&content_key.inner, item_id, &content).map_err(js_err)
}

/// Decrypt an item body sealed under its per-item content key.
#[wasm_bindgen(js_name = "itemBodyDecryptWithContentKey")]
pub fn item_body_decrypt_with_content_key(
    content_key: &WasmItemContentKey,
    item_id: &[u8],
    blob: &[u8],
) -> Result<String, JsError> {
    if item_id.len() != 16 {
        return Err(JsError::new("item_id must be 16 bytes (UUID)"));
    }
    let content =
        crate_decrypt_item_with_content_key(&content_key.inner, item_id, blob).map_err(js_err)?;
    serde_json::to_string(content.as_ref()).map_err(js_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_derive_bounds_reject_out_of_range_params() {
        // Oversized memory request from an untrusted profile must not reach
        // the allocator.
        assert!(check_kdf_derive_bounds(0, 1, 1, 32, 16).is_err());
        assert!(check_kdf_derive_bounds(7, 1, 1, 32, 16).is_err());
        assert!(check_kdf_derive_bounds(u32::MAX, 1, 1, 32, 16).is_err());
        assert!(check_kdf_derive_bounds(8, 0, 1, 32, 16).is_err());
        assert!(check_kdf_derive_bounds(8, KDF_MAX_TIME_COST + 1, 1, 32, 16).is_err());
        assert!(check_kdf_derive_bounds(8, 1, 0, 32, 16).is_err());
        assert!(check_kdf_derive_bounds(8, 1, KDF_MAX_PARALLELISM + 1, 32, 16).is_err());
        assert!(check_kdf_derive_bounds(8, 1, 1, 8, 16).is_err());
        assert!(check_kdf_derive_bounds(8, 1, 1, 1 << 20, 16).is_err());
        assert!(check_kdf_derive_bounds(8, 1, 1, 32, 2048).is_err());
        // The probe profile and the default profile stay derivable.
        check_kdf_derive_bounds(8 * 1024, 1, 1, 32, 16).unwrap();
        check_kdf_derive_bounds(64 * 1024, 2, 1, 32, 16).unwrap();
    }

    #[test]
    fn create_agent_canonical_bytes_are_stable() {
        let provenance = serde_json::json!({ "kind": "hosted_mcp" });
        let canonical = canonical_create_agent_bytes(
            "Hosted MCP",
            &[1; X25519_KEY_LEN],
            &[2; ED25519_PUBLIC_LEN],
            &provenance,
            1_777_777_777,
            "00000000-0000-0000-0000-000000000000",
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            concat!(
                r#"{"display_name":"Hosted MCP","issued_at":1777777777,"#,
                r#""kem_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","#,
                r#""key_provenance":{"kind":"hosted_mcp"},"kms_key_id":null,"#,
                r#""nonce":"00000000-0000-0000-0000-000000000000","#,
                r#""signing_public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}"#
            )
        );
    }

    #[test]
    fn create_agent_sign_matches_canonical_bytes() {
        let owner = IdentitySigningKeypair::generate();
        let owner_private = WasmSigningPrivateKey {
            inner: owner.private.clone(),
        };
        let agent_kem = IdentityKemKeypair::generate();
        let agent_signing = IdentitySigningKeypair::generate();
        let provenance = serde_json::json!({ "kind": "hosted_mcp" });
        let provenance_json = serde_json::to_string(&provenance).unwrap();
        let issued_at = 1_777_777_777;
        let nonce = Uuid::nil().to_string();

        let signature = create_agent_sign(
            &owner_private,
            "Hosted MCP",
            agent_kem.public.as_bytes(),
            agent_signing.public.as_bytes(),
            &provenance_json,
            issued_at,
            &nonce,
        )
        .unwrap();

        let canonical = canonical_create_agent_bytes(
            "Hosted MCP",
            agent_kem.public.as_bytes(),
            agent_signing.public.as_bytes(),
            &provenance,
            issued_at,
            &nonce,
        )
        .unwrap();
        signing::verify(&owner.public, &canonical, &signature).unwrap();
    }

    #[test]
    fn hosted_agent_sign_matches_server_canonical_bytes() {
        let owner = IdentitySigningKeypair::generate();
        let owner_private = WasmSigningPrivateKey {
            inner: owner.private.clone(),
        };
        let provenance = serde_json::json!({
            "kind": "hosted_agent",
            "context": "seren-cloud-agent:00000000-0000-0000-0000-000000000000"
        });
        let issued_at = 1_777_777_777;
        let nonce = Uuid::nil().to_string();

        let signature = hosted_agent_sign(
            &owner_private,
            "Cloud agent",
            &serde_json::to_string(&provenance).unwrap(),
            issued_at,
            &nonce,
        )
        .unwrap();
        let canonical = serde_json::to_vec(&serde_json::json!({
            "display_name": "Cloud agent",
            "key_provenance": provenance,
            "issued_at": issued_at,
            "nonce": nonce,
        }))
        .unwrap();
        signing::verify(&owner.public, &canonical, &signature).unwrap();
    }

    #[test]
    fn membership_grant_domain_is_seren_secrets() {
        let signed =
            seren_secrets_crypto::protocol::membership_grant::membership_grant_signing_bytes(
                &[1; 16],
                &[2; 16],
                3,
                &[4, 5],
            );
        assert!(signed.starts_with(b"seren-secrets/membership-grant"));
        assert_eq!(
            &signed[b"seren-secrets/membership-grant".len()..],
            &[
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 3, 4, 5,
            ]
        );
    }
}
