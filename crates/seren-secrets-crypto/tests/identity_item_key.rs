use seren_secrets_crypto::{
    CryptoError, kem,
    keys::{IdentityKemKeypair, ItemContentKey},
    protocol::item::unwrap_item_content_key_for_identity,
};

#[test]
fn unwraps_identity_sealed_item_key() {
    let identity = IdentityKemKeypair::generate();
    let key = ItemContentKey::random();
    let sealed = kem::seal(&identity.public, key.as_bytes());
    let unwrapped = unwrap_item_content_key_for_identity(&identity.private, &sealed).unwrap();
    assert_eq!(unwrapped.as_bytes(), key.as_bytes());
    assert!(!format!("{unwrapped:?}").contains(&format!("{:?}", key.as_bytes())));
    let other = IdentityKemKeypair::generate();
    assert!(matches!(
        unwrap_item_content_key_for_identity(&other.private, &sealed),
        Err(CryptoError::AuthFailure)
    ));
    assert!(unwrap_item_content_key_for_identity(&identity.private, &[]).is_err());
}

#[test]
fn refuses_identity_sealed_plaintext_of_any_other_length() {
    let identity = IdentityKemKeypair::generate();
    for length in [0, 1, 31, 33, 64] {
        let sealed = kem::seal(&identity.public, &vec![42; length]);
        let error = unwrap_item_content_key_for_identity(&identity.private, &sealed).unwrap_err();
        assert!(matches!(error, CryptoError::InvalidCiphertext));
        assert!(!format!("{error}\n{error:?}").contains("42, 42"));
    }
}
