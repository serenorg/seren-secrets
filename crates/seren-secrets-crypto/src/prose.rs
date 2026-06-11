//! ProseMirror content format for typed item bodies.
//!
//! `SecureNoteContent.body`, `LoginContent.notes`, and
//! `ApiCredentialContent.notes` are stored as ProseMirror JSON so the entire
//! Seren ecosystem shares a single rich-text representation. This is a typed
//! content choice; ciphertext handling is unchanged.
//!
//! ## Attachment URI scheme
//!
//! Inline attachment references inside a ProseMirror tree use the URI
//! `seren-secrets://attachment/<attachment_uuid>`. The UUID matches the
//! `id` column of the `item_attachments` row that holds the encrypted blob.
//!
//! ## Plain-text companion
//!
//! Every body has a `_text` sibling field with the plain-text projection of
//! the doc. Clients use it for list previews, full-text search indexing,
//! and minimal UIs that do not embed a ProseMirror renderer. The text is
//! derived from the doc on every write; if the two ever disagree, the
//! ProseMirror JSON is canonical.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use seren_secrets_macros::RedactedDebug;

/// URI scheme that inline attachment nodes use to reference rows in
/// `item_attachments`.
pub const ATTACHMENT_URI_SCHEME: &str = "seren-secrets://attachment/";

/// Build a fresh empty ProseMirror document. Prefer
/// [`ProseDoc::empty`] in new code; this raw helper exists for callers
/// that want a `serde_json::Value` directly (tests, JSON fixtures).
pub fn empty_doc() -> Value {
    json!({ "type": "doc", "content": [] })
}

/// A ProseMirror document.
///
/// Construction is gated through this newtype so the field invariant
/// "the inner value is a JSON object with `type == "doc"`" is enforced at
/// the type level rather than via serde attributes. Deserialize normalizes
/// `null`, missing, or non-doc-shaped input into [`ProseDoc::empty`], so
/// `LoginContent::notes`, `SecureNoteContent::body`, and
/// `ApiCredentialContent::notes` can never decode into a `Value::Null` that
/// silently fails to render.
///
/// The newtype is transparent on the wire: it serializes as the inner
/// `Value`, so ciphertext shape is unchanged from earlier revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ProseDoc(Value);

impl ProseDoc {
    /// Empty ProseMirror document (`{"type": "doc", "content": []}`).
    pub fn empty() -> Self {
        Self(empty_doc())
    }

    /// Wrap an existing `serde_json::Value`. Inputs that are `Null`, not an
    /// object, whose `type` field is not the string `"doc"`, or whose
    /// `content` field is present but not an array collapse to
    /// [`ProseDoc::empty`]. Strict schema validation of the inner node
    /// shapes (paragraph attrs, mark kinds, attachment hrefs) is the
    /// responsibility of the rendering client; this gate only protects the
    /// outer-shape invariant that downstream code can assume: the value is
    /// an object, `type == "doc"`, and `content` is iterable.
    pub fn from_value_lossy(value: Value) -> Self {
        if is_doc_shape(&value) {
            Self(value)
        } else {
            Self::empty()
        }
    }

    /// Borrow the inner `Value` for read-only inspection.
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    /// Consume the wrapper and return the inner `Value`.
    pub fn into_value(self) -> Value {
        self.0
    }

    /// Plain-text projection of the document, suitable for previews and
    /// full-text search indexing.
    pub fn plain_text(&self) -> String {
        to_plaintext(&self.0)
    }
}

impl Default for ProseDoc {
    fn default() -> Self {
        Self::empty()
    }
}

impl zeroize::Zeroize for ProseDoc {
    fn zeroize(&mut self) {
        zeroize_json_strings(&mut self.0);
    }
}

/// Recursively zeroize every string value inside a JSON tree in place.
///
/// Object keys are field names rather than secret values, so they are left
/// intact; string values, array elements, and nested objects are scrubbed.
/// Shared with `protocol::item` so the loss-preserving `raw_import` buckets
/// and prose bodies are scrubbed by the same walk.
pub(crate) fn zeroize_json_strings(value: &mut Value) {
    use zeroize::Zeroize;
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_json_strings),
        Value::Object(map) => map.values_mut().for_each(zeroize_json_strings),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// `serde_json::Value` wrapper that zeroizes all string bytes when scrubbed.
///
/// Use for loss-preserving import buckets (`raw_import` on all item content
/// types) and any other JSON blob that may contain plaintext from a decrypted
/// item. The wire format is identical to a bare `Value` thanks to the
/// `#[serde(transparent)]` attribute.
#[derive(Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ZeroizableJson(pub serde_json::Value);

impl ZeroizableJson {
    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }

    pub fn into_value(self) -> serde_json::Value {
        self.0
    }
}

impl From<serde_json::Value> for ZeroizableJson {
    fn from(v: serde_json::Value) -> Self {
        Self(v)
    }
}

impl zeroize::Zeroize for ZeroizableJson {
    fn zeroize(&mut self) {
        zeroize_json_strings(&mut self.0);
    }
}

impl std::ops::Deref for ZeroizableJson {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ZeroizableJson {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'de> Deserialize<'de> for ProseDoc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Ok(Self::from_value_lossy(value))
    }
}

/// True if `value` is a JSON object with `type == "doc"` and, if `content`
/// is present, it is an array. Individual node shapes inside `content` are
/// not validated here; that is the renderer's job. Accepting a missing
/// `content` key keeps forward-compat with future producers, but a present
/// non-array `content` is rejected because every renderer in the ecosystem
/// iterates that field.
fn is_doc_shape(value: &Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    if obj.get("type").and_then(Value::as_str) != Some("doc") {
        return false;
    }
    match obj.get("content") {
        None => true,
        Some(c) => c.is_array(),
    }
}

/// Wrap a plain-text string as a minimal ProseMirror document, preserving
/// line breaks as paragraph boundaries. Empty input returns
/// [`ProseDoc::empty`].
///
/// Returns `(doc, plaintext)` so callers can populate both the JSON body
/// and its `_text` companion in one call.
pub fn from_plaintext(text: &str) -> (ProseDoc, String) {
    if text.is_empty() {
        return (ProseDoc::empty(), String::new());
    }
    let paragraphs: Vec<Value> = text
        .split('\n')
        .map(|line| {
            if line.is_empty() {
                json!({ "type": "paragraph" })
            } else {
                json!({
                    "type": "paragraph",
                    "content": [{ "type": "text", "text": line }],
                })
            }
        })
        .collect();
    let doc = json!({ "type": "doc", "content": paragraphs });
    (ProseDoc(doc), text.to_string())
}

/// Parse GitHub-Flavored Markdown into a ProseMirror document under the
/// `seren-secrets://` attachment scheme. The companion plain-text is the
/// extracted text projection so list views and search can use it directly.
///
/// Falls back to [`from_plaintext`] if the markdown parser rejects the
/// input.
pub fn from_markdown(markdown: &str) -> (ProseDoc, String) {
    if markdown.is_empty() {
        return (ProseDoc::empty(), String::new());
    }
    let converter = seren_prosemirror::ProseMirror::new(ATTACHMENT_URI_SCHEME);
    match converter.markdown_to_prosemirror(markdown) {
        Ok(doc) => {
            let text = seren_prosemirror::extract_plain_text(&doc);
            (ProseDoc::from_value_lossy(doc), text)
        }
        Err(_) => from_plaintext(markdown),
    }
}

/// Walk a ProseMirror document `Value` and return its plain-text projection.
/// Suitable for raw-`Value` call sites; prefer [`ProseDoc::plain_text`] when
/// you already hold a [`ProseDoc`].
pub fn to_plaintext(doc: &Value) -> String {
    seren_prosemirror::extract_plain_text(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_doc_is_a_valid_prosemirror_doc() {
        let doc = empty_doc();
        assert_eq!(doc["type"], "doc");
        assert!(doc["content"].as_array().unwrap().is_empty());
    }

    #[test]
    fn plaintext_round_trips_through_paragraphs() {
        let (doc, text) = from_plaintext("hello\nworld");
        assert_eq!(text, "hello\nworld");
        let inner = doc.as_value();
        let paragraphs = inner["content"].as_array().unwrap();
        assert_eq!(paragraphs.len(), 2);
        assert_eq!(paragraphs[0]["content"][0]["text"], "hello");
        assert_eq!(paragraphs[1]["content"][0]["text"], "world");
    }

    #[test]
    fn plaintext_preserves_blank_lines_as_empty_paragraphs() {
        let (doc, text) = from_plaintext("a\n\nb");
        assert_eq!(text, "a\n\nb");
        let paragraphs = doc.as_value()["content"].as_array().unwrap();
        assert_eq!(paragraphs.len(), 3);
        assert!(paragraphs[1].get("content").is_none());
    }

    #[test]
    fn empty_input_is_empty_doc() {
        let (doc, text) = from_plaintext("");
        assert_eq!(text, "");
        assert!(doc.as_value()["content"].as_array().unwrap().is_empty());
    }

    #[test]
    fn markdown_lifts_into_prosemirror() {
        let (doc, text) = from_markdown("**bold** *italic*");
        // We do not pin the exact tree shape (that is the seren-prosemirror
        // crate's contract), but the doc must be valid and the plaintext
        // must contain the visible characters.
        assert_eq!(doc.as_value()["type"], "doc");
        assert!(text.contains("bold"));
        assert!(text.contains("italic"));
    }

    #[test]
    fn markdown_recognizes_service_name_attachment_scheme() {
        let attachment_id = "00000000-0000-0000-0000-000000000001";
        let markdown = format!("[file.pdf]({ATTACHMENT_URI_SCHEME}{attachment_id})");
        let (doc, text) = from_markdown(&markdown);

        assert_eq!(text, "file.pdf");
        let node = &doc.as_value()["content"][0];
        assert_eq!(node["type"], "attachment");
        assert_eq!(node["attrs"]["attachmentId"], attachment_id);
        assert_eq!(node["attrs"]["filename"], "file.pdf");
    }

    #[test]
    fn to_plaintext_is_consistent_with_from_plaintext() {
        let (doc, text) = from_plaintext("line one\nline two");
        assert_eq!(doc.plain_text(), text);
    }

    #[test]
    fn prosedoc_default_is_empty_doc_not_null() {
        let doc = ProseDoc::default();
        assert_eq!(doc, ProseDoc::empty());
        assert_eq!(doc.as_value()["type"], "doc");
    }

    #[test]
    fn deserialize_normalizes_json_null_to_empty_doc() {
        let doc: ProseDoc = serde_json::from_value(Value::Null).unwrap();
        assert_eq!(doc, ProseDoc::empty());
    }

    #[test]
    fn deserialize_normalizes_non_doc_object_to_empty_doc() {
        // Collapse non-doc objects to the empty canonical body.
        let doc: ProseDoc = serde_json::from_value(json!({"foo": "bar"})).unwrap();
        assert_eq!(doc, ProseDoc::empty());
    }

    #[test]
    fn deserialize_rejects_non_array_content() {
        // A doc with type == "doc" but a scalar `content` would crash any
        // renderer that walks the content array. Collapse it instead of
        // letting the malformed shape survive as the canonical body.
        let doc: ProseDoc =
            serde_json::from_value(json!({"type": "doc", "content": "oops"})).unwrap();
        assert_eq!(doc, ProseDoc::empty());
        let doc: ProseDoc =
            serde_json::from_value(json!({"type": "doc", "content": {"k": "v"}})).unwrap();
        assert_eq!(doc, ProseDoc::empty());
    }

    #[test]
    fn deserialize_accepts_doc_without_content_key() {
        // Forward-compat: a producer that omits an empty content array is
        // still a valid doc; renderers should treat missing content as
        // empty rather than crashing.
        let doc: ProseDoc = serde_json::from_value(json!({"type": "doc"})).unwrap();
        assert_eq!(doc.as_value()["type"], "doc");
    }

    #[test]
    fn deserialize_preserves_well_shaped_doc() {
        let raw = json!({
            "type": "doc",
            "content": [{
                "type": "paragraph",
                "content": [{ "type": "text", "text": "kept" }],
            }],
        });
        let doc: ProseDoc = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(doc.as_value(), &raw);
        assert_eq!(doc.plain_text(), "kept");
    }

    #[test]
    fn serialize_is_transparent() {
        let (doc, _) = from_plaintext("hi");
        let inner = doc.as_value().clone();
        let serialized = serde_json::to_value(&doc).unwrap();
        assert_eq!(serialized, inner);
    }
}
