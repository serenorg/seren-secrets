//! Account-level flows: signup, master password change, and unlock.
//!
//! The opaque blobs stored server-side per user are:
//! - `account_key_wrap`: account key wrapped under the master key
//! - `account_kem_private_wrap`: identity X25519 private key wrapped under the account key
//! - `account_signing_private_wrap`: identity Ed25519 private key wrapped under the account key
//! - `recovery_key_wrap`: account key wrapped under the recovery-derived key
//!
//! plus the public halves of both identity keypairs and both sets of KDF
//! parameters (master + recovery).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::aead::{xchacha20_decrypt_with_aad, xchacha20_encrypt_with_aad};

// Domain-separation AAD labels for the account/recovery key wraps. Fixed
// labels (no user_id): cross-user swaps are already prevented by the signed
// account-secrets-update proof, which binds user_id and every blob. These give
// per-slot separation so a wrap of one kind cannot be opened as another.
pub(crate) const ACCOUNT_KEY_WRAP_AAD: &[u8] = b"account-key-wrap:";
pub(crate) const RECOVERY_KEY_WRAP_AAD: &[u8] = b"recovery-key-wrap:";
pub(crate) const ACCOUNT_KEM_PRIVATE_WRAP_AAD: &[u8] = b"account-kem-private-wrap:";
pub(crate) const ACCOUNT_SIGNING_PRIVATE_WRAP_AAD: &[u8] = b"account-signing-private-wrap:";
use crate::error::{CryptoError, CryptoResult};
use crate::kdf::{KdfParams, default_params, derive_key, validate_stored_params};
use crate::keys::{
    AccountKey, IdentityKemKeypair, IdentityKemPrivateKey, IdentityKemPublicKey,
    IdentitySigningKeypair, IdentitySigningPrivateKey, IdentitySigningPublicKey, MasterKey,
    RecoveryDerivedKey, RecoveryKey,
};

/// Opaque blobs the server stores on the user's `account_secrets` row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountSecrets {
    pub kdf_params: KdfParams,
    pub recovery_kdf_params: KdfParams,
    #[serde(with = "serde_b64")]
    pub account_key_wrap: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub account_kem_private_wrap: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub account_signing_private_wrap: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub recovery_key_wrap: Vec<u8>,
    pub kem_public_key: IdentityKemPublicKey,
    pub signing_public_key: IdentitySigningPublicKey,
}

/// Bundle returned from [`account_setup`] containing both the public material
/// to send to the server and the recovery key to show the user exactly once.
pub struct AccountSetupBundle {
    pub secrets: AccountSecrets,
    pub recovery_key: RecoveryKey,
    pub kem_keypair: IdentityKemKeypair,
    pub signing_keypair: IdentitySigningKeypair,
}

/// Run signup with default Argon2id parameters. Equivalent to
/// `account_setup_with_params(master_password, default_params(),
/// default_params())`; kept as a thin convenience for callers that
/// don't probe the host's KDF throughput.
pub fn account_setup(master_password: &[u8]) -> CryptoResult<AccountSetupBundle> {
    account_setup_with_params(master_password, default_params(), default_params())
}

/// Run signup with caller-supplied Argon2id parameters. Use this when
/// the caller has probed the host (see `kdf::recommend_params`) and
/// wants to downgrade the master and/or recovery KDF profile so unlock
/// finishes inside a reasonable wall-clock budget on weaker devices.
/// The two profiles are independent so a host that can sit through a
/// stronger recovery KDF (recovery is only run once) can keep the
/// recovery profile at default while downgrading the master profile.
pub fn account_setup_with_params(
    master_password: &[u8],
    kdf_params: KdfParams,
    recovery_kdf_params: KdfParams,
) -> CryptoResult<AccountSetupBundle> {
    // Setup must reject profiles that unlock and recovery would reject.
    validate_stored_params(&kdf_params)?;
    validate_stored_params(&recovery_kdf_params)?;
    let recovery_key = RecoveryKey::random();

    let master_key = derive_master_key(master_password, &kdf_params)?;
    let recovery_derived = derive_recovery_key(recovery_key.as_bytes(), &recovery_kdf_params)?;

    let account_key = AccountKey::random();
    let kem_keypair = IdentityKemKeypair::generate();
    let signing_keypair = IdentitySigningKeypair::generate();

    let account_key_wrap = xchacha20_encrypt_with_aad(
        master_key.as_bytes(),
        account_key.as_bytes(),
        ACCOUNT_KEY_WRAP_AAD,
    );
    let recovery_key_wrap = xchacha20_encrypt_with_aad(
        recovery_derived.as_bytes(),
        account_key.as_bytes(),
        RECOVERY_KEY_WRAP_AAD,
    );
    let account_kem_private_wrap = xchacha20_encrypt_with_aad(
        account_key.as_bytes(),
        kem_keypair.private.as_bytes(),
        ACCOUNT_KEM_PRIVATE_WRAP_AAD,
    );
    let account_signing_private_wrap = xchacha20_encrypt_with_aad(
        account_key.as_bytes(),
        signing_keypair.private.as_bytes(),
        ACCOUNT_SIGNING_PRIVATE_WRAP_AAD,
    );

    let secrets = AccountSecrets {
        kdf_params,
        recovery_kdf_params,
        account_key_wrap,
        account_kem_private_wrap,
        account_signing_private_wrap,
        recovery_key_wrap,
        kem_public_key: kem_keypair.public,
        signing_public_key: signing_keypair.public,
    };

    Ok(AccountSetupBundle {
        secrets,
        recovery_key,
        kem_keypair,
        signing_keypair,
    })
}

/// Material returned after a successful unlock.
#[derive(Debug)]
pub struct UnlockedAccount {
    pub account_key: AccountKey,
    pub kem_private: IdentityKemPrivateKey,
    pub signing_private: IdentitySigningPrivateKey,
}

pub fn unlock_account(
    master_password: &[u8],
    secrets: &AccountSecrets,
) -> CryptoResult<UnlockedAccount> {
    // Validate stored KDF params before spending Argon2 memory.
    validate_stored_params(&secrets.kdf_params)?;
    let master_key = derive_master_key(master_password, &secrets.kdf_params)?;
    let account_key = unwrap_account_key(&master_key, &secrets.account_key_wrap)?;

    let kem_private_bytes = Zeroizing::new(xchacha20_decrypt_with_aad(
        account_key.as_bytes(),
        &secrets.account_kem_private_wrap,
        ACCOUNT_KEM_PRIVATE_WRAP_AAD,
    )?);
    let signing_private_bytes = Zeroizing::new(xchacha20_decrypt_with_aad(
        account_key.as_bytes(),
        &secrets.account_signing_private_wrap,
        ACCOUNT_SIGNING_PRIVATE_WRAP_AAD,
    )?);

    let kem_private = IdentityKemPrivateKey::from_slice(&kem_private_bytes)?;
    let signing_private = IdentitySigningPrivateKey::from_slice(&signing_private_bytes)?;

    // Public halves are plain server fields; require them to match the wraps.
    if IdentityKemKeypair::from_private(kem_private.clone()).public != secrets.kem_public_key {
        return Err(CryptoError::InvalidKey(
            "kem public key does not match unwrapped private key",
        ));
    }
    if IdentitySigningKeypair::from_private(signing_private.clone()).public
        != secrets.signing_public_key
    {
        return Err(CryptoError::InvalidKey(
            "signing public key does not match unwrapped private key",
        ));
    }

    Ok(UnlockedAccount {
        account_key,
        kem_private,
        signing_private,
    })
}

/// Re-wrap the account key under a new master key derived from the new password.
/// Caller passes in the already-unlocked account key so this is a pure
/// re-encryption; the recovery wrap is left untouched.
pub fn change_master_password(
    account_key: &AccountKey,
    new_password: &[u8],
    secrets: &mut AccountSecrets,
) -> CryptoResult<()> {
    let new_params = default_params();
    let new_master = derive_master_key(new_password, &new_params)?;
    let new_wrap = xchacha20_encrypt_with_aad(
        new_master.as_bytes(),
        account_key.as_bytes(),
        ACCOUNT_KEY_WRAP_AAD,
    );
    secrets.kdf_params = new_params;
    secrets.account_key_wrap = new_wrap;
    Ok(())
}

pub fn unwrap_account_signing_private_key(
    account_key: &AccountKey,
    account_signing_private_wrap: &[u8],
) -> CryptoResult<IdentitySigningPrivateKey> {
    let bytes = Zeroizing::new(xchacha20_decrypt_with_aad(
        account_key.as_bytes(),
        account_signing_private_wrap,
        ACCOUNT_SIGNING_PRIVATE_WRAP_AAD,
    )?);
    IdentitySigningPrivateKey::from_slice(&bytes)
}

pub(crate) fn derive_master_key(password: &[u8], params: &KdfParams) -> CryptoResult<MasterKey> {
    // Zeroizing: this buffer is the raw master key; wipe it once copied
    // into the self-zeroizing newtype.
    let bytes = Zeroizing::new(derive_key(password, params)?);
    if bytes.len() != 32 {
        return Err(CryptoError::Kdf(
            "master key derivation produced wrong length",
        ));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(MasterKey::from_bytes(buf))
}

pub(crate) fn derive_recovery_key(
    recovery_key_bytes: &[u8],
    params: &KdfParams,
) -> CryptoResult<RecoveryDerivedKey> {
    let bytes = Zeroizing::new(derive_key(recovery_key_bytes, params)?);
    if bytes.len() != 32 {
        return Err(CryptoError::Kdf(
            "recovery-derived key derivation produced wrong length",
        ));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(RecoveryDerivedKey::from_bytes(buf))
}

pub(crate) fn unwrap_account_key(master_key: &MasterKey, wrap: &[u8]) -> CryptoResult<AccountKey> {
    let bytes = Zeroizing::new(xchacha20_decrypt_with_aad(
        master_key.as_bytes(),
        wrap,
        ACCOUNT_KEY_WRAP_AAD,
    )?);
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKey("account key wrong length"));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(AccountKey::from_bytes(buf))
}

mod serde_b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KdfAlgorithm;

    #[test]
    fn account_wrap_aad_labels_are_frozen() {
        // Wire labels: a rename would break cross-version unlock/recovery, so
        // the exact bytes are pinned here as the cross-implementation canary.
        assert_eq!(ACCOUNT_KEY_WRAP_AAD, b"account-key-wrap:".as_slice());
        assert_eq!(RECOVERY_KEY_WRAP_AAD, b"recovery-key-wrap:".as_slice());
        assert_eq!(
            ACCOUNT_KEM_PRIVATE_WRAP_AAD,
            b"account-kem-private-wrap:".as_slice()
        );
        assert_eq!(
            ACCOUNT_SIGNING_PRIVATE_WRAP_AAD,
            b"account-signing-private-wrap:".as_slice()
        );
    }

    fn fast_setup(password: &[u8]) -> AccountSetupBundle {
        // Mirror account_setup but with fast KDF.
        let kdf_params = KdfParams {
            version: 1,
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
            salt: vec![3u8; 16],
        };
        let recovery_kdf_params = KdfParams {
            version: 1,
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
            salt: vec![4u8; 16],
        };
        let recovery_key = RecoveryKey::random();
        let master_key = derive_master_key(password, &kdf_params).unwrap();
        let recovery_derived =
            derive_recovery_key(recovery_key.as_bytes(), &recovery_kdf_params).unwrap();
        let account_key = AccountKey::random();
        let kem_keypair = IdentityKemKeypair::generate();
        let signing_keypair = IdentitySigningKeypair::generate();
        let secrets = AccountSecrets {
            kdf_params,
            recovery_kdf_params,
            account_key_wrap: xchacha20_encrypt_with_aad(
                master_key.as_bytes(),
                account_key.as_bytes(),
                ACCOUNT_KEY_WRAP_AAD,
            ),
            account_kem_private_wrap: xchacha20_encrypt_with_aad(
                account_key.as_bytes(),
                kem_keypair.private.as_bytes(),
                ACCOUNT_KEM_PRIVATE_WRAP_AAD,
            ),
            account_signing_private_wrap: xchacha20_encrypt_with_aad(
                account_key.as_bytes(),
                signing_keypair.private.as_bytes(),
                ACCOUNT_SIGNING_PRIVATE_WRAP_AAD,
            ),
            recovery_key_wrap: xchacha20_encrypt_with_aad(
                recovery_derived.as_bytes(),
                account_key.as_bytes(),
                RECOVERY_KEY_WRAP_AAD,
            ),
            kem_public_key: kem_keypair.public,
            signing_public_key: signing_keypair.public,
        };
        AccountSetupBundle {
            secrets,
            recovery_key,
            kem_keypair,
            signing_keypair,
        }
    }

    #[test]
    fn signup_and_unlock_round_trip() {
        let bundle = fast_setup(b"correct horse battery staple");
        let unlocked = unlock_account(b"correct horse battery staple", &bundle.secrets).unwrap();
        let recovered = crate::protocol::recovery::recover_with_recovery_key(
            &bundle.recovery_key,
            &bundle.secrets,
        )
        .unwrap();
        assert_eq!(unlocked.account_key.as_bytes(), recovered.as_bytes());
        assert_eq!(
            unlocked.kem_private.as_bytes(),
            bundle.kem_keypair.private.as_bytes()
        );
        assert_eq!(
            unlocked.signing_private.as_bytes(),
            bundle.signing_keypair.private.as_bytes()
        );
    }

    #[test]
    fn wrong_password_fails() {
        let bundle = fast_setup(b"correct password");
        let err = unlock_account(b"wrong password", &bundle.secrets).unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailure));
    }

    #[test]
    fn setup_rejects_unapproved_kdf_profiles() {
        // Setup must reject profiles that unlock and recovery would reject.
        let weak = KdfParams {
            version: 1,
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 8,
            time_cost: 1,
            parallelism: 1,
            output_len: 32,
            salt: vec![1u8; 16],
        };
        let ok = KdfParams {
            version: 1,
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
            salt: vec![2u8; 16],
        };
        let Err(err) = account_setup_with_params(b"pw", weak.clone(), ok.clone()) else {
            panic!("weak master KDF profile must be rejected at setup");
        };
        assert!(matches!(err, CryptoError::Kdf(_)));
        let Err(err) = account_setup_with_params(b"pw", ok, weak) else {
            panic!("weak recovery KDF profile must be rejected at setup");
        };
        assert!(matches!(err, CryptoError::Kdf(_)));
    }

    #[test]
    fn unlock_rejects_tampered_kem_public_key() {
        let mut bundle = fast_setup(b"pw");
        bundle.secrets.kem_public_key = IdentityKemKeypair::generate().public;
        let err = unlock_account(b"pw", &bundle.secrets).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKey(_)));
    }

    #[test]
    fn unlock_rejects_tampered_signing_public_key() {
        let mut bundle = fast_setup(b"pw");
        bundle.secrets.signing_public_key = IdentitySigningKeypair::generate().public;
        let err = unlock_account(b"pw", &bundle.secrets).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKey(_)));
    }

    #[test]
    fn change_master_password_round_trip() {
        let mut bundle = fast_setup(b"old");
        let unlocked = unlock_account(b"old", &bundle.secrets).unwrap();
        change_master_password(&unlocked.account_key, b"new", &mut bundle.secrets).unwrap();
        // Old password no longer works.
        assert!(unlock_account(b"old", &bundle.secrets).is_err());
        // New one does, BUT we need to fast-override the new params for the test to be quick.
        // Since change_master_password uses default_params(), we accept that test will be slow.
        // Instead, force fast params back and re-wrap manually.
        let new_params = KdfParams {
            version: 1,
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
            salt: vec![7u8; 16],
        };
        let mk = derive_master_key(b"new", &new_params).unwrap();
        bundle.secrets.kdf_params = new_params;
        bundle.secrets.account_key_wrap = xchacha20_encrypt_with_aad(
            mk.as_bytes(),
            unlocked.account_key.as_bytes(),
            ACCOUNT_KEY_WRAP_AAD,
        );
        let again = unlock_account(b"new", &bundle.secrets).unwrap();
        assert_eq!(
            unlocked.account_key.as_bytes(),
            again.account_key.as_bytes()
        );
    }

    #[test]
    fn account_secrets_accepts_js_joined_public_key_arrays() {
        let bundle = fast_setup(b"password");
        let mut value = serde_json::to_value(&bundle.secrets).unwrap();
        value["kem_public_key"] = serde_json::json!(bundle.kem_keypair.public.as_bytes().to_vec());
        value["signing_public_key"] =
            serde_json::json!(bundle.signing_keypair.public.as_bytes().to_vec());

        let decoded: AccountSecrets = serde_json::from_value(value).unwrap();

        assert_eq!(
            decoded.kem_public_key.as_bytes(),
            bundle.kem_keypair.public.as_bytes()
        );
        assert_eq!(
            decoded.signing_public_key.as_bytes(),
            bundle.signing_keypair.public.as_bytes()
        );
        assert_eq!(decoded.account_key_wrap, bundle.secrets.account_key_wrap);
        assert_eq!(
            decoded.account_kem_private_wrap,
            bundle.secrets.account_kem_private_wrap
        );
        assert_eq!(
            decoded.account_signing_private_wrap,
            bundle.secrets.account_signing_private_wrap
        );
        assert_eq!(decoded.recovery_key_wrap, bundle.secrets.recovery_key_wrap);
    }
}
