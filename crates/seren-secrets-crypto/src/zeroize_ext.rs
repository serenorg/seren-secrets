//! Zeroize-capable container newtypes.
//!
//! The `zeroize` crate's `BTreeMap` impl can only zero values (keys are
//! immutable via `iter_mut`). `ZeroizableBTreeMap` drains the map so both
//! keys and values are overwritten before the backing memory is freed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use seren_secrets_macros::RedactedDebug;

/// `BTreeMap<K, V>` that zeroizes both keys and values by draining the map
/// before drop. Wire format is unchanged from a plain `BTreeMap` thanks to
/// `#[serde(transparent)]`.
#[derive(Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ZeroizableBTreeMap<K: Ord, V>(pub BTreeMap<K, V>);

impl<K: Ord> ZeroizableBTreeMap<K, String> {
    pub fn as_map(&self) -> &BTreeMap<K, String> {
        &self.0
    }

    pub fn into_map(self) -> BTreeMap<K, String> {
        self.0
    }
}

impl<K: zeroize::Zeroize + Ord, V: zeroize::Zeroize> zeroize::Zeroize for ZeroizableBTreeMap<K, V> {
    fn zeroize(&mut self) {
        for (mut k, mut v) in std::mem::take(&mut self.0) {
            k.zeroize();
            v.zeroize();
        }
    }
}

impl<K: Ord, V> From<BTreeMap<K, V>> for ZeroizableBTreeMap<K, V> {
    fn from(map: BTreeMap<K, V>) -> Self {
        Self(map)
    }
}

impl<K: Ord, V> std::ops::Deref for ZeroizableBTreeMap<K, V> {
    type Target = BTreeMap<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K: Ord, V> std::ops::DerefMut for ZeroizableBTreeMap<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
