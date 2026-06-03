//! Vault key generation, wrapping, unwrapping, and encrypted vault metadata.

use crate::aead::{xchacha20_decrypt_with_aad, xchacha20_encrypt_with_aad};
use crate::error::CryptoResult;
use crate::kem::{seal, unseal};
use crate::keys::{IdentityKemPrivateKey, IdentityKemPublicKey, VaultKey};

pub fn generate_vault_key() -> VaultKey {
    VaultKey::random()
}

/// Wrap (encrypt) the given vault key so the holder of `recipient`'s private
/// key can recover it.
pub fn wrap_vault_key_for_identity(
    vault_key: &VaultKey,
    recipient: &IdentityKemPublicKey,
) -> Vec<u8> {
    seal(recipient, vault_key.as_bytes())
}

/// Unwrap a vault key previously wrapped with [`wrap_vault_key_for_identity`].
pub fn unwrap_vault_key(private: &IdentityKemPrivateKey, wrapped: &[u8]) -> CryptoResult<VaultKey> {
    let bytes = unseal(private, wrapped)?;
    if bytes.len() != 32 {
        return Err(crate::error::CryptoError::InvalidKey(
            "wrapped vault key was not 32 bytes",
        ));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(VaultKey::from_bytes(buf))
}

fn vault_name_aad(vault_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(vault_id.len() + 11);
    aad.extend_from_slice(b"vault-name:");
    aad.extend_from_slice(vault_id);
    aad
}

fn vault_description_aad(vault_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(vault_id.len() + 18);
    aad.extend_from_slice(b"vault-description:");
    aad.extend_from_slice(vault_id);
    aad
}

fn vault_invitation_email_aad(vault_id: &[u8], invitation_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(vault_id.len() + invitation_id.len() + 24);
    aad.extend_from_slice(b"vault-invitation-email:");
    aad.extend_from_slice(vault_id);
    aad.push(b':');
    aad.extend_from_slice(invitation_id);
    aad
}

fn live_share_recipient_email_aad(vault_id: &[u8], share_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(vault_id.len() + share_id.len() + 28);
    aad.extend_from_slice(b"live-share-recipient-email:");
    aad.extend_from_slice(vault_id);
    aad.push(b':');
    aad.extend_from_slice(share_id);
    aad
}

pub fn encrypt_vault_name(vault_key: &VaultKey, vault_id: &[u8], name: &str) -> Vec<u8> {
    xchacha20_encrypt_with_aad(
        vault_key.as_bytes(),
        name.as_bytes(),
        &vault_name_aad(vault_id),
    )
}

pub fn decrypt_vault_name(
    vault_key: &VaultKey,
    vault_id: &[u8],
    blob: &[u8],
) -> CryptoResult<String> {
    let pt = xchacha20_decrypt_with_aad(vault_key.as_bytes(), blob, &vault_name_aad(vault_id))?;
    String::from_utf8(pt).map_err(|_| crate::error::CryptoError::InvalidCiphertext)
}

pub fn encrypt_vault_description(
    vault_key: &VaultKey,
    vault_id: &[u8],
    description: &str,
) -> Vec<u8> {
    xchacha20_encrypt_with_aad(
        vault_key.as_bytes(),
        description.as_bytes(),
        &vault_description_aad(vault_id),
    )
}

pub fn decrypt_vault_description(
    vault_key: &VaultKey,
    vault_id: &[u8],
    blob: &[u8],
) -> CryptoResult<String> {
    let pt =
        xchacha20_decrypt_with_aad(vault_key.as_bytes(), blob, &vault_description_aad(vault_id))?;
    String::from_utf8(pt).map_err(|_| crate::error::CryptoError::InvalidCiphertext)
}

pub fn encrypt_vault_invitation_email(
    vault_key: &VaultKey,
    vault_id: &[u8],
    invitation_id: &[u8],
    email: &str,
) -> Vec<u8> {
    xchacha20_encrypt_with_aad(
        vault_key.as_bytes(),
        email.as_bytes(),
        &vault_invitation_email_aad(vault_id, invitation_id),
    )
}

pub fn decrypt_vault_invitation_email(
    vault_key: &VaultKey,
    vault_id: &[u8],
    invitation_id: &[u8],
    blob: &[u8],
) -> CryptoResult<String> {
    let pt = xchacha20_decrypt_with_aad(
        vault_key.as_bytes(),
        blob,
        &vault_invitation_email_aad(vault_id, invitation_id),
    )?;
    String::from_utf8(pt).map_err(|_| crate::error::CryptoError::InvalidCiphertext)
}

pub fn encrypt_live_share_recipient_email(
    vault_key: &VaultKey,
    vault_id: &[u8],
    share_id: &[u8],
    email: &str,
) -> Vec<u8> {
    xchacha20_encrypt_with_aad(
        vault_key.as_bytes(),
        email.as_bytes(),
        &live_share_recipient_email_aad(vault_id, share_id),
    )
}

pub fn decrypt_live_share_recipient_email(
    vault_key: &VaultKey,
    vault_id: &[u8],
    share_id: &[u8],
    blob: &[u8],
) -> CryptoResult<String> {
    let pt = xchacha20_decrypt_with_aad(
        vault_key.as_bytes(),
        blob,
        &live_share_recipient_email_aad(vault_id, share_id),
    )?;
    String::from_utf8(pt).map_err(|_| crate::error::CryptoError::InvalidCiphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKemKeypair;

    fn expect1(prefix: &[u8], id: &[u8]) -> Vec<u8> {
        let mut v = prefix.to_vec();
        v.extend_from_slice(id);
        v
    }

    fn expect2(prefix: &[u8], id1: &[u8], id2: &[u8]) -> Vec<u8> {
        let mut v = prefix.to_vec();
        v.extend_from_slice(id1);
        v.push(b':');
        v.extend_from_slice(id2);
        v
    }

    /// Frozen AAD layout for vault slots. The two-id email slots bind their ids
    /// with a ':' separator (CRYPTO-1); pinned so a layout change is deliberate
    /// and lockstepped with the KAT and clients.
    #[test]
    fn vault_aad_layout_is_frozen() {
        let vault_id = [0x11u8; 16];
        let second_id = [0x22u8; 16];
        assert_eq!(
            vault_name_aad(&vault_id),
            expect1(b"vault-name:", &vault_id)
        );
        assert_eq!(
            vault_description_aad(&vault_id),
            expect1(b"vault-description:", &vault_id)
        );
        assert_eq!(
            vault_invitation_email_aad(&vault_id, &second_id),
            expect2(b"vault-invitation-email:", &vault_id, &second_id)
        );
        assert_eq!(
            live_share_recipient_email_aad(&vault_id, &second_id),
            expect2(b"live-share-recipient-email:", &vault_id, &second_id)
        );
    }

    #[test]
    fn round_trip_wrap_unwrap() {
        let vk = generate_vault_key();
        let kp = IdentityKemKeypair::generate();
        let wrapped = wrap_vault_key_for_identity(&vk, &kp.public);
        let unwrapped = unwrap_vault_key(&kp.private, &wrapped).unwrap();
        assert_eq!(vk.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn wrong_recipient_fails() {
        let vk = generate_vault_key();
        let kp1 = IdentityKemKeypair::generate();
        let kp2 = IdentityKemKeypair::generate();
        let wrapped = wrap_vault_key_for_identity(&vk, &kp1.public);
        let err = unwrap_vault_key(&kp2.private, &wrapped).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::AuthFailure));
    }

    #[test]
    fn vault_metadata_round_trips_and_binds_vault_id() {
        let vk = generate_vault_key();
        let vault_a = uuid::Uuid::new_v4();
        let vault_b = uuid::Uuid::new_v4();

        let name = encrypt_vault_name(&vk, vault_a.as_bytes(), "Personal");
        assert_eq!(
            decrypt_vault_name(&vk, vault_a.as_bytes(), &name).unwrap(),
            "Personal"
        );
        assert!(decrypt_vault_name(&vk, vault_b.as_bytes(), &name).is_err());

        let desc = encrypt_vault_description(&vk, vault_a.as_bytes(), "Shared ops");
        assert_eq!(
            decrypt_vault_description(&vk, vault_a.as_bytes(), &desc).unwrap(),
            "Shared ops"
        );
        assert!(decrypt_vault_description(&vk, vault_b.as_bytes(), &desc).is_err());

        let invite_a = uuid::Uuid::new_v4();
        let invite_b = uuid::Uuid::new_v4();
        let invite = encrypt_vault_invitation_email(
            &vk,
            vault_a.as_bytes(),
            invite_a.as_bytes(),
            "a@example.com",
        );
        assert_eq!(
            decrypt_vault_invitation_email(&vk, vault_a.as_bytes(), invite_a.as_bytes(), &invite)
                .unwrap(),
            "a@example.com"
        );
        assert!(
            decrypt_vault_invitation_email(&vk, vault_b.as_bytes(), invite_a.as_bytes(), &invite)
                .is_err()
        );
        assert!(
            decrypt_vault_invitation_email(&vk, vault_a.as_bytes(), invite_b.as_bytes(), &invite)
                .is_err()
        );

        let share_a = uuid::Uuid::new_v4();
        let share_b = uuid::Uuid::new_v4();
        let email = encrypt_live_share_recipient_email(
            &vk,
            vault_a.as_bytes(),
            share_a.as_bytes(),
            "recipient@example.com",
        );
        assert_eq!(
            decrypt_live_share_recipient_email(&vk, vault_a.as_bytes(), share_a.as_bytes(), &email)
                .unwrap(),
            "recipient@example.com"
        );
        assert!(
            decrypt_live_share_recipient_email(&vk, vault_b.as_bytes(), share_a.as_bytes(), &email)
                .is_err()
        );
        assert!(
            decrypt_live_share_recipient_email(&vk, vault_a.as_bytes(), share_b.as_bytes(), &email)
                .is_err()
        );
    }
}
