//! Exact server-supplied item revisions for optimistic concurrency, and
//! exact server-supplied lifecycle timestamps.

use std::fmt;
use std::str::FromStr;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::error::ResolverError;

/// An RFC3339 item revision that retains the server's exact spelling.
///
/// Offsets and fractional precision are preserved when serialized or sent in
/// an `If-Match` header. Equality compares the representation, not the instant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct ItemRevision(String);

impl ItemRevision {
    /// Validate an RFC3339 revision without normalizing its representation.
    pub fn new(value: impl Into<String>) -> Result<Self, ResolverError> {
        let value = value.into();
        if !valid_rfc3339(&value) {
            return Err(ResolverError::InvalidInput("item revision must be RFC3339"));
        }
        Ok(Self(value))
    }

    /// Return the original server-supplied revision.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ItemRevision {
    type Err = ResolverError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ItemRevision {
    type Error = ResolverError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ItemRevision> for String {
    fn from(value: ItemRevision) -> Self {
        value.0
    }
}

impl AsRef<str> for ItemRevision {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ItemRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An RFC3339 lifecycle timestamp, such as a trash or creation time, that
/// retains the server's exact spelling.
///
/// It is validated like [`ItemRevision`] but is a distinct type, so it can never
/// be sent as an `If-Match` revision. Equality compares the representation,
/// not the instant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct ServiceTimestamp(String);

impl ServiceTimestamp {
    /// Validate an RFC3339 timestamp without normalizing its representation.
    pub fn new(value: impl Into<String>) -> Result<Self, ResolverError> {
        let value = value.into();
        if !valid_rfc3339(&value) {
            return Err(ResolverError::InvalidInput("timestamp must be RFC3339"));
        }
        Ok(Self(value))
    }

    /// Return the original server-supplied timestamp.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ServiceTimestamp {
    type Err = ResolverError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ServiceTimestamp {
    type Error = ResolverError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ServiceTimestamp> for String {
    fn from(value: ServiceTimestamp) -> Self {
        value.0
    }
}

impl AsRef<str> for ServiceTimestamp {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ServiceTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn valid_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
        || !bytes[..19]
            .iter()
            .enumerate()
            .all(|(i, byte)| matches!(i, 4 | 7 | 10 | 13 | 16) || byte.is_ascii_digit())
    {
        return false;
    }
    let mut offset_start = 19;
    if bytes[offset_start] == b'.' {
        offset_start += 1;
        while bytes.get(offset_start).is_some_and(u8::is_ascii_digit) {
            offset_start += 1;
        }
        if offset_start == 20 {
            return false;
        }
    }
    let offset = &bytes[offset_start..];
    if !(matches!(offset, [b'Z' | b'z'])
        || offset.len() == 6
            && matches!(offset[0], b'+' | b'-')
            && offset[3] == b':'
            && [offset[1], offset[2], offset[4], offset[5]]
                .iter()
                .all(u8::is_ascii_digit)
            && (offset[1] - b'0') * 10 + offset[2] - b'0' <= 23
            && (offset[4] - b'0') * 10 + offset[5] - b'0' <= 59)
    {
        return false;
    }
    // RFC3339 permits arbitrary fractional precision. Jiff validates calendar
    // and offset values using its supported nanosecond precision only.
    if offset_start > 29 {
        let mut timestamp = value[..29].to_string();
        timestamp.push_str(&value[offset_start..]);
        timestamp.parse::<Timestamp>().is_ok()
    } else {
        value.parse::<Timestamp>().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: [&str; 6] = [
        "2026-10-17T12:34:56Z",
        "2026-10-17T12:34:56.123400+05:30",
        "2026-10-17t12:34:56.123456789012z",
        "2026-10-17T12:34:56.000000-00:00",
        "2026-10-17T12:34:56.250Z",
        "2026-10-17T12:34:56.1234+05:30",
    ];

    const INVALID: [&str; 9] = [
        "",
        "2026-02-30T12:34:56Z",
        "2026-10-17T12:34:56",
        "2026-10-17 12:34:56Z",
        "2026-10-17T12:34:56.Z",
        "2026-10-17T12:34:56+24:00",
        "2026-10-17T12:34:56+00:00:00",
        "2026-10-17T12:34:56Z[UTC]",
        "2026-10-17T12:34:56Z\r\nheader: value",
    ];

    #[test]
    fn revisions_preserve_rfc3339_spelling_through_serde() {
        for original in VALID {
            let revision = ItemRevision::new(original).unwrap();
            assert_eq!(revision.as_str(), original);
            assert_eq!(revision.to_string(), original);
            let json = serde_json::to_string(&revision).unwrap();
            assert_eq!(json, serde_json::to_string(original).unwrap());
            let decoded: ItemRevision = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, revision);
        }
    }

    #[test]
    fn revisions_reject_invalid_dates_and_non_rfc3339_forms() {
        for invalid in INVALID {
            assert!(ItemRevision::new(invalid).is_err(), "{invalid:?}");
            assert!(
                serde_json::from_value::<ItemRevision>(serde_json::json!(invalid)).is_err(),
                "{invalid:?}"
            );
        }
        for invalid in [serde_json::Value::Null, serde_json::json!(42)] {
            assert!(serde_json::from_value::<ItemRevision>(invalid).is_err());
        }
    }

    #[test]
    fn service_timestamps_accept_exactly_what_revisions_accept_and_keep_its_text() {
        for value in VALID.iter().chain(&INVALID) {
            assert_eq!(
                ServiceTimestamp::new(*value).is_ok(),
                ItemRevision::new(*value).is_ok(),
                "{value:?}"
            );
        }
        for original in VALID {
            let timestamp = ServiceTimestamp::new(original).unwrap();
            assert_eq!(timestamp.as_str(), original);
            assert_eq!(AsRef::<str>::as_ref(&timestamp), original);
            assert_eq!(timestamp.to_string(), original);
            assert_eq!(original.parse::<ServiceTimestamp>().unwrap(), timestamp);
            assert_eq!(
                ServiceTimestamp::try_from(original.to_owned()).unwrap(),
                timestamp
            );
            let json = serde_json::to_string(&timestamp).unwrap();
            assert_eq!(json, serde_json::to_string(original).unwrap());
            let decoded: ServiceTimestamp = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, timestamp);
            assert_eq!(String::from(timestamp), original);
        }
        for invalid in INVALID {
            assert!(ServiceTimestamp::new(invalid).is_err(), "{invalid:?}");
            assert!(invalid.parse::<ServiceTimestamp>().is_err(), "{invalid:?}");
            assert!(
                serde_json::from_value::<ServiceTimestamp>(serde_json::json!(invalid)).is_err(),
                "{invalid:?}"
            );
        }
        for invalid in [serde_json::Value::Null, serde_json::json!(42)] {
            assert!(serde_json::from_value::<ServiceTimestamp>(invalid).is_err());
        }
    }

    #[test]
    fn service_timestamps_compare_by_text_not_instant() {
        let trimmed = ServiceTimestamp::new("2026-10-17T12:34:56.25Z").unwrap();
        let padded = ServiceTimestamp::new("2026-10-17T12:34:56.250Z").unwrap();
        let offset = ServiceTimestamp::new("2026-10-17T18:04:56.25+05:30").unwrap();
        assert_eq!(
            padded,
            ServiceTimestamp::new("2026-10-17T12:34:56.250Z").unwrap()
        );
        let instant = trimmed.as_str().parse::<Timestamp>().unwrap();
        for other in [&padded, &offset] {
            // The same instant, spelled differently, is a different value.
            assert_eq!(other.as_str().parse::<Timestamp>().unwrap(), instant);
            assert_ne!(*other, trimmed);
        }
        assert_ne!(padded, offset);
    }
}
