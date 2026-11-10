use seren_secrets_crypto::{
    kem,
    keys::{IdentityKemKeypair, ItemContentKey},
    protocol::item::{
        CardContent, ItemContent, LoginContent, PostalAddress, SecureNoteContent,
        encrypt_item_with_content_key,
    },
};
use seren_secrets_resolver::{
    BrowserGrantError, BrowserGrantFields, FieldProjectionError, project_field, read_browser_grant,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const USERNAME: &str = "browser-grant-user@example.test";
const PASSWORD: &str = "browser-grant-password-never-log";
const CARDHOLDER: &str = "Browser Grant Test Cardholder";
const NUMBER: &str = "4111222233334444";
const CVV: &str = "836";
const POSTAL: &str = "94041";
const EXPIRY: &str = "07/29";
const NOTE: &str = "secure-note-must-not-be-read";

struct Grant {
    id: Uuid,
    identity: IdentityKemKeypair,
    key: ItemContentKey,
    ciphertext: Vec<u8>,
    wrapped_key: Vec<u8>,
}

impl Grant {
    fn new(content: &ItemContent) -> Self {
        let id = Uuid::new_v4();
        let identity = IdentityKemKeypair::generate();
        let key = ItemContentKey::random();
        let ciphertext = encrypt_item_with_content_key(&key, id.as_bytes(), content).unwrap();
        // Exactly itemContentKeyWrapForIdentity's wire operation.
        let wrapped_key = kem::seal(&identity.public, key.as_bytes());
        Self {
            id,
            identity,
            key,
            ciphertext,
            wrapped_key,
        }
    }

    fn read(&self, kind: &str, fields: &[&str]) -> Result<BrowserGrantFields, BrowserGrantError> {
        read_browser_grant(
            self.id,
            kind,
            &self.ciphertext,
            &self.wrapped_key,
            &self.identity.private,
            fields,
        )
    }

    fn assert_redacted(&self, output: impl std::fmt::Debug + std::fmt::Display) {
        let rendered = format!("{output}\n{output:?}");
        for secret in [
            USERNAME, PASSWORD, CARDHOLDER, NUMBER, CVV, POSTAL, EXPIRY, NOTE,
        ] {
            assert!(!rendered.contains(secret), "secret leaked in output");
        }
        for bytes in [self.key.as_bytes(), self.identity.private.as_bytes()] {
            let hex = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let base64 = {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(bytes)
            };
            assert!(!rendered.contains(&hex));
            assert!(!rendered.contains(&base64));
            assert!(!rendered.contains(&format!("{bytes:?}")));
        }
    }
}

fn login() -> ItemContent {
    ItemContent::Login(LoginContent {
        username: USERNAME.into(),
        password: PASSWORD.into(),
        ..Default::default()
    })
}

fn card() -> ItemContent {
    ItemContent::Card(CardContent {
        cardholder_name: CARDHOLDER.into(),
        number: NUMBER.into(),
        expiry: EXPIRY.into(),
        cvv: CVV.into(),
        billing_address: Some(PostalAddress {
            postal_code: POSTAL.into(),
            ..Default::default()
        }),
        ..Default::default()
    })
}

#[test]
fn reads_login_and_only_requested_fields() {
    let grant = Grant::new(&login());
    let fields = grant
        .read("login", &["username", "password", "USER", "pass"])
        .unwrap();
    for (name, expected) in [
        ("username", USERNAME),
        ("password", PASSWORD),
        ("USER", USERNAME),
        ("pass", PASSWORD),
    ] {
        assert_eq!(fields.get(name), Some(expected));
    }
    assert_eq!(fields.len(), 4);
    grant.assert_redacted(format!("{fields:?}"));
    let subset = grant.read("login", &["username"]).unwrap();
    assert_eq!(subset.len(), 1);
    assert_eq!(subset.get("password"), None);
    let empty = grant.read("login", &[]).unwrap();
    assert!(empty.is_empty());
}

#[test]
fn reads_all_card_fields_and_aliases_with_four_digit_year() {
    let grant = Grant::new(&card());
    let expected = [
        ("cardholder_name", CARDHOLDER),
        ("number", NUMBER),
        ("pan", NUMBER),
        ("expiry", EXPIRY),
        ("expiry_month", "07"),
        ("expiry_year", "2029"),
        ("cvv", CVV),
        ("billing_postal_code", POSTAL),
    ];
    let names = expected.map(|(name, _)| name);
    let fields = grant.read("card", &names).unwrap();
    assert_eq!(fields.len(), expected.len());
    for (name, value) in expected {
        assert_eq!(fields.get(name), Some(value));
    }
    assert_eq!(fields.get("pin"), None);
    grant.assert_redacted(format!("{fields:?}"));
}

#[test]
fn public_projection_reuses_aliases_and_zeroizes_values() {
    let content = card();
    let value: Zeroizing<String> = project_field(&content, "PAN").unwrap();
    assert_eq!(value.as_str(), NUMBER);
    assert_eq!(
        project_field(&content, "exp_year").unwrap().as_str(),
        "2029"
    );
    assert_eq!(project_field(&login(), "user").unwrap().as_str(), USERNAME);
    assert_eq!(
        project_field(&content, PASSWORD).unwrap_err(),
        FieldProjectionError::UnknownField
    );
    let grant = Grant::new(&content);
    grant.assert_redacted(project_field(&content, PASSWORD).unwrap_err());
}

#[test]
fn refuses_wrong_key_item_and_tampered_ciphertext_without_leaks() {
    let mut grant = Grant::new(&login());
    let other = IdentityKemKeypair::generate();
    let error = read_browser_grant(
        grant.id,
        "login",
        &grant.ciphertext,
        &grant.wrapped_key,
        &other.private,
        &["password"],
    )
    .unwrap_err();
    assert_eq!(error, BrowserGrantError::KeyUnwrap);
    grant.assert_redacted(error);
    let error = read_browser_grant(
        Uuid::new_v4(),
        "login",
        &grant.ciphertext,
        &grant.wrapped_key,
        &grant.identity.private,
        &["password"],
    )
    .unwrap_err();
    assert_eq!(error, BrowserGrantError::ItemMismatch);
    grant.assert_redacted(error);
    let last = grant.ciphertext.len() - 1;
    grant.ciphertext[last] ^= 1;
    let error = grant.read("login", &["password"]).unwrap_err();
    assert_eq!(error, BrowserGrantError::ItemMismatch);
    grant.assert_redacted(error);
    grant.wrapped_key.clear();
    let error = grant.read("login", &["password"]).unwrap_err();
    assert_eq!(error, BrowserGrantError::KeyUnwrap);
    grant.assert_redacted(error);
}

#[test]
fn refuses_authenticated_malformed_item_content_without_leaks() {
    let mut grant = Grant::new(&login());
    let mut aad = b"body:".to_vec();
    aad.extend_from_slice(grant.id.as_bytes());
    for malformed in [PASSWORD.as_bytes(), br#"{"kind":"login","password":123}"#] {
        grant.ciphertext = seren_secrets_crypto::aead::xchacha20_encrypt_with_aad(
            grant.key.as_bytes(),
            malformed,
            &aad,
        );
        let error = grant.read("login", &["password"]).unwrap_err();
        assert_eq!(error, BrowserGrantError::InvalidContent);
        grant.assert_redacted(error);
    }
}

#[test]
fn refuses_kind_mismatch_and_every_unsupported_declared_kind() {
    for (content, declared) in [(login(), "card"), (card(), "login")] {
        let grant = Grant::new(&content);
        let error = grant.read(declared, &["number"]).unwrap_err();
        assert_eq!(error, BrowserGrantError::KindMismatch);
        grant.assert_redacted(error);
    }
    let grant = Grant::new(&ItemContent::SecureNote(SecureNoteContent {
        body_text: NOTE.into(),
        ..Default::default()
    }));
    for declared in [
        "secure_note",
        "api_credential",
        "identity",
        "document",
        "ssh_key",
        "server",
        "database",
        "bank_account",
        "passport",
        "driver_license",
        "crypto_wallet",
        PASSWORD,
        "",
        "Login",
    ] {
        let error = grant.read(declared, &["body"]).unwrap_err();
        assert_eq!(error, BrowserGrantError::UnsupportedKind);
        grant.assert_redacted(error);
    }
    for declared in ["login", "card"] {
        let error = grant.read(declared, &["body"]).unwrap_err();
        assert_eq!(error, BrowserGrantError::UnsupportedKind);
        grant.assert_redacted(error);
    }
}

#[test]
fn refuses_unknown_or_empty_fields_atomically_and_redacts_invalid_values() {
    let grant = Grant::new(&login());
    for field in ["unknown", PASSWORD, USERNAME, "", "totp"] {
        let error = grant.read("login", &["username", field]).unwrap_err();
        assert_eq!(
            error,
            BrowserGrantError::Field(FieldProjectionError::UnknownField)
        );
        grant.assert_redacted(error);
    }
    let mut content = card();
    if let ItemContent::Card(card) = &mut content {
        card.expiry = PASSWORD.into();
    }
    let grant = Grant::new(&content);
    let error = grant.read("card", &["number", "expiry_month"]).unwrap_err();
    assert_eq!(
        error,
        BrowserGrantError::Field(FieldProjectionError::InvalidValue)
    );
    grant.assert_redacted(error);
    let grant = Grant::new(&ItemContent::Login(LoginContent::default()));
    let error = grant.read("login", &["password"]).unwrap_err();
    assert_eq!(
        error,
        BrowserGrantError::Field(FieldProjectionError::UnknownField)
    );
    grant.assert_redacted(error);
}
