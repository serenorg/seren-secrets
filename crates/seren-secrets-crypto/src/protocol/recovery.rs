//! Recovery flows for the master-password-lost case.

use zeroize::Zeroizing;

use crate::aead::{xchacha20_decrypt_with_aad, xchacha20_encrypt_with_aad};
use crate::error::{CryptoError, CryptoResult};
use crate::kdf::{default_params, validate_stored_params};
use crate::keys::{AccountKey, RecoveryKey};
use crate::protocol::account::{ACCOUNT_KEY_WRAP_AAD, RECOVERY_KEY_WRAP_AAD};
use crate::protocol::account::{AccountSecrets, derive_master_key, derive_recovery_key};

/// Recover the account key using the user-provided recovery key.
pub fn recover_with_recovery_key(
    recovery_key: &RecoveryKey,
    secrets: &AccountSecrets,
) -> CryptoResult<AccountKey> {
    // Same guard as unlock: validate server-supplied params before Argon2.
    validate_stored_params(&secrets.recovery_kdf_params)?;
    let derived = derive_recovery_key(recovery_key.as_bytes(), &secrets.recovery_kdf_params)?;
    // Zeroizing: this buffer is the raw account key; wipe it once copied
    // into the self-zeroizing newtype.
    let bytes = Zeroizing::new(xchacha20_decrypt_with_aad(
        derived.as_bytes(),
        &secrets.recovery_key_wrap,
        RECOVERY_KEY_WRAP_AAD,
    )?);
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKey(
            "recovered account key wrong length",
        ));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(AccountKey::from_bytes(buf))
}

/// Rotate the recovery key. Caller must already have an unlocked `account_key`.
/// Updates `secrets.recovery_key_wrap` and `secrets.recovery_kdf_params` in place;
/// returns the freshly-generated recovery key the client should show to the user.
pub fn regenerate_recovery_key(
    account_key: &AccountKey,
    secrets: &mut AccountSecrets,
) -> CryptoResult<RecoveryKey> {
    let new_params = default_params();
    let new_recovery_key = RecoveryKey::random();
    let derived = derive_recovery_key(new_recovery_key.as_bytes(), &new_params)?;
    secrets.recovery_kdf_params = new_params;
    secrets.recovery_key_wrap = xchacha20_encrypt_with_aad(
        derived.as_bytes(),
        account_key.as_bytes(),
        RECOVERY_KEY_WRAP_AAD,
    );
    Ok(new_recovery_key)
}

/// After a recovery, re-wrap the account key under a new master password and
/// rotate the Recovery Key so the consumed Recovery Sheet cannot be reused.
pub fn rewrap_account_key_after_recovery(
    account_key: &AccountKey,
    new_password: &[u8],
    secrets: &mut AccountSecrets,
) -> CryptoResult<RecoveryKey> {
    let new_params = default_params();
    let mk = derive_master_key(new_password, &new_params)?;
    secrets.kdf_params = new_params;
    secrets.account_key_wrap =
        xchacha20_encrypt_with_aad(mk.as_bytes(), account_key.as_bytes(), ACCOUNT_KEY_WRAP_AAD);
    regenerate_recovery_key(account_key, secrets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{KdfAlgorithm, KdfParams};
    use crate::keys::{IdentityKemKeypair, IdentitySigningKeypair};

    fn fast_setup() -> (AccountSecrets, RecoveryKey, AccountKey) {
        let p = KdfParams {
            version: 1,
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
            salt: vec![5u8; 16],
        };
        let rk = RecoveryKey::random();
        let derived = derive_recovery_key(rk.as_bytes(), &p).unwrap();
        let account_key = AccountKey::random();
        let kem = IdentityKemKeypair::generate();
        let signing = IdentitySigningKeypair::generate();
        let secrets = AccountSecrets {
            kdf_params: p.clone(),
            recovery_kdf_params: p,
            account_key_wrap: vec![],
            account_kem_private_wrap: xchacha20_encrypt_with_aad(
                account_key.as_bytes(),
                kem.private.as_bytes(),
                crate::protocol::account::ACCOUNT_KEM_PRIVATE_WRAP_AAD,
            ),
            account_signing_private_wrap: xchacha20_encrypt_with_aad(
                account_key.as_bytes(),
                signing.private.as_bytes(),
                crate::protocol::account::ACCOUNT_SIGNING_PRIVATE_WRAP_AAD,
            ),
            recovery_key_wrap: xchacha20_encrypt_with_aad(
                derived.as_bytes(),
                account_key.as_bytes(),
                RECOVERY_KEY_WRAP_AAD,
            ),
            kem_public_key: kem.public,
            signing_public_key: signing.public,
        };
        (secrets, rk, account_key)
    }

    #[test]
    fn recovery_round_trip() {
        let (secrets, rk, ak) = fast_setup();
        let recovered = recover_with_recovery_key(&rk, &secrets).unwrap();
        assert_eq!(recovered.as_bytes(), ak.as_bytes());
    }

    #[test]
    fn wrong_recovery_key_fails() {
        let (secrets, _rk, _ak) = fast_setup();
        let wrong = RecoveryKey::random();
        let err = recover_with_recovery_key(&wrong, &secrets).unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailure));
    }

    #[test]
    fn rewrap_after_recovery_rotates_recovery_key() {
        let (mut secrets, old_recovery_key, account_key) = fast_setup();
        let new_recovery_key =
            rewrap_account_key_after_recovery(&account_key, b"new password", &mut secrets).unwrap();

        let old_err = recover_with_recovery_key(&old_recovery_key, &secrets).unwrap_err();
        assert!(matches!(old_err, CryptoError::AuthFailure));

        let recovered = recover_with_recovery_key(&new_recovery_key, &secrets).unwrap();
        assert_eq!(recovered.as_bytes(), account_key.as_bytes());
    }
}
