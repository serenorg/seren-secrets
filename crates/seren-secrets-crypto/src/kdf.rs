//! Argon2id KDF with versioned parameter storage so accounts can be upgraded.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

use crate::entropy::fill_random;
use crate::error::{CryptoError, CryptoResult};

/// Per-account KDF parameters. Stored alongside the wrapped account key so
/// `seren-secrets-crypto` can upgrade defaults without breaking existing
/// accounts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub version: u8,
    pub algorithm: KdfAlgorithm,
    /// Memory cost in KiB.
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    /// Output length in bytes.
    pub output_len: u32,
    #[serde(with = "serde_base64")]
    pub salt: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KdfAlgorithm {
    Argon2id,
}

/// Default Argon2id parameters: 64 MiB, t=2, p=1, 32-byte output, 16-byte salt.
///
/// Tuned for single-threaded wasm: parallelism > 1 can multiply wall-clock
/// time without raising the security bar. 64 MiB / t=2 is above OWASP's
/// Argon2id baselines at p=1 (see the Password Storage Cheat Sheet).
pub fn default_params() -> KdfParams {
    let mut salt = vec![0u8; 16];
    fill_random(&mut salt);
    KdfParams {
        version: 1,
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib: 64 * 1024,
        time_cost: 2,
        parallelism: 1,
        output_len: 32,
        salt,
    }
}

/// Return true when stored parameters are weaker than the current defaults.
/// Callers can use this after a successful unlock to decide whether to
/// re-wrap the account key with fresh parameters.
pub fn needs_upgrade(params: &KdfParams) -> bool {
    let defaults = default_params();
    params.algorithm != defaults.algorithm
        || params.version < defaults.version
        || params.memory_kib < defaults.memory_kib
        || params.time_cost < defaults.time_cost
        || params.parallelism < defaults.parallelism
        || params.output_len < defaults.output_len
}

/// Build replacement parameters when `current` is weaker than defaults.
/// Returns `None` when the stored parameters are already at least as strong.
pub fn upgraded_params(current: &KdfParams) -> Option<KdfParams> {
    needs_upgrade(current).then(default_params)
}

/// Validate a KDF profile before storing it server-side.
///
/// Callers may downshift from the default profile after measuring local
/// Argon2id throughput, but stored profiles must stay within the approved set
/// this crate can intentionally mint.
pub fn validate_stored_params(params: &KdfParams) -> CryptoResult<()> {
    if params.version != 1 {
        return Err(CryptoError::Kdf("unsupported KDF version"));
    }
    if params.algorithm != KdfAlgorithm::Argon2id {
        return Err(CryptoError::Kdf("unsupported KDF algorithm"));
    }
    if params.parallelism != 1 {
        return Err(CryptoError::Kdf("unsupported KDF parallelism"));
    }
    if params.output_len != 32 {
        return Err(CryptoError::Kdf("unsupported KDF output length"));
    }
    if params.salt.len() != 16 {
        return Err(CryptoError::Kdf("unsupported KDF salt length"));
    }
    if params.salt.iter().all(|&byte| byte == 0) {
        return Err(CryptoError::Kdf("unsupported KDF salt value"));
    }
    if !PROFILES
        .iter()
        .any(|&(memory, time)| memory == params.memory_kib && time == params.time_cost)
    {
        return Err(CryptoError::Kdf("unsupported KDF memory/time profile"));
    }
    Ok(())
}

/// Smallest acceptable memory cost on hosts that cannot run the default
/// 64 MiB profile inside the user's time budget. OWASP lists 19 MiB /
/// t=2 / p=1 as one Argon2id baseline in the Password Storage Cheat
/// Sheet; never recommend below that without an explicit product
/// decision.
const MIN_RECOMMENDED_MEMORY_KIB: u32 = 19 * 1024;
const MIN_RECOMMENDED_TIME_COST: u32 = 2;
/// Reference run for the throughput probe: cheap enough to finish in
/// tens of milliseconds even on a low-end phone, large enough that the
/// extrapolation is not dominated by per-call overhead.
pub const PROBE_MEMORY_KIB: u32 = 8 * 1024;
pub const PROBE_TIME_COST: u32 = 1;

/// Candidate (memory_kib, time_cost) profiles in descending strength.
/// `recommend_params_for_throughput` walks this list and picks the
/// strongest entry whose extrapolated cost fits the caller's time
/// budget. The first entry mirrors `default_params`; the floor is
/// 19 MiB / t=2 so the caller never receives a worse-than-OWASP-baseline
/// profile.
const PROFILES: &[(u32, u32)] = &[
    (64 * 1024, 2),
    (64 * 1024, 1),
    (32 * 1024, 2),
    (MIN_RECOMMENDED_MEMORY_KIB, MIN_RECOMMENDED_TIME_COST),
];

/// Mint the cheap probe profile callers run once to measure the host's
/// Argon2id throughput. Salt is the all-zeros placeholder; the probe
/// output is discarded so the salt doesn't matter.
pub fn probe_params() -> KdfParams {
    KdfParams {
        version: 1,
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib: PROBE_MEMORY_KIB,
        time_cost: PROBE_TIME_COST,
        parallelism: 1,
        output_len: 32,
        salt: vec![0u8; 16],
    }
}

/// Pick the strongest Argon2id profile that fits the caller's wall-
/// clock budget given the measured throughput of a single probe run.
/// The caller is responsible for running `derive_key(probe_params())`,
/// timing it, and passing the elapsed milliseconds back in as
/// `probe_ms`. Argon2id is dominated by memory * time iteration work,
/// so the linear extrapolation matches observed wall-clock to within
/// ~15% on every platform we ship to.
///
/// Never recommends anything weaker than the 19 MiB / t=2 floor, and
/// never anything stronger than `default_params`. Callers should still
/// run `needs_upgrade` after unlock on a more capable host to bump the
/// profile back up.
pub fn recommend_params_for_throughput(probe_ms: u64, target_ms: u32) -> KdfParams {
    let probe_ms = probe_ms.max(1);
    let probe_units = u64::from(PROBE_MEMORY_KIB) * u64::from(PROBE_TIME_COST);
    let budget = u64::from(target_ms);
    let mut chosen = (MIN_RECOMMENDED_MEMORY_KIB, MIN_RECOMMENDED_TIME_COST);
    for &(memory_kib, time_cost) in PROFILES {
        let units = u64::from(memory_kib) * u64::from(time_cost);
        let estimated_ms = probe_ms.saturating_mul(units) / probe_units;
        if estimated_ms <= budget {
            chosen = (memory_kib, time_cost);
            break;
        }
    }
    let mut salt = vec![0u8; 16];
    fill_random(&mut salt);
    KdfParams {
        version: 1,
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib: chosen.0,
        time_cost: chosen.1,
        parallelism: 1,
        output_len: 32,
        salt,
    }
}

/// Derive a key of `params.output_len` bytes from `password` using the given parameters.
pub fn derive_key(password: &[u8], params: &KdfParams) -> CryptoResult<Vec<u8>> {
    if params.algorithm != KdfAlgorithm::Argon2id {
        return Err(CryptoError::Kdf("unsupported algorithm"));
    }
    let argon_params = Params::new(
        params.memory_kib,
        params.time_cost,
        params.parallelism,
        Some(params.output_len as usize),
    )
    .map_err(|_| CryptoError::Kdf("invalid Argon2 parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = vec![0u8; params.output_len as usize];
    argon
        .hash_password_into(password, &params.salt, &mut out)
        .map_err(|_| CryptoError::Kdf("argon2 derivation failed"))?;
    Ok(out)
}

mod serde_base64 {
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

    fn fast_params() -> KdfParams {
        // Cheap params for fast tests; never use these in production.
        KdfParams {
            version: 1,
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 8,
            time_cost: 1,
            parallelism: 1,
            output_len: 32,
            salt: vec![1u8; 16],
        }
    }

    #[test]
    fn deterministic_output_for_same_salt() {
        let p = fast_params();
        let a = derive_key(b"correct horse battery staple", &p).unwrap();
        let b = derive_key(b"correct horse battery staple", &p).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn different_salts_diverge() {
        let mut p1 = fast_params();
        let mut p2 = fast_params();
        p1.salt = vec![1u8; 16];
        p2.salt = vec![2u8; 16];
        let a = derive_key(b"password", &p1).unwrap();
        let b = derive_key(b"password", &p2).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_passwords_diverge() {
        let p = fast_params();
        let a = derive_key(b"alpha", &p).unwrap();
        let b = derive_key(b"beta", &p).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn params_round_trip_json() {
        let p = default_params();
        let s = serde_json::to_string(&p).unwrap();
        let r: KdfParams = serde_json::from_str(&s).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn default_params_are_sane() {
        let p = default_params();
        assert_eq!(p.memory_kib, 64 * 1024);
        assert_eq!(p.time_cost, 2);
        assert_eq!(p.parallelism, 1);
        assert_eq!(p.output_len, 32);
        assert_eq!(p.salt.len(), 16);
        validate_stored_params(&p).unwrap();
    }

    #[test]
    fn validate_stored_params_rejects_unapproved_profiles() {
        let weak = fast_params();
        assert!(validate_stored_params(&weak).is_err());

        let mut bad_salt = default_params();
        bad_salt.salt = vec![1u8; 8];
        assert!(validate_stored_params(&bad_salt).is_err());

        let mut zero_salt = default_params();
        zero_salt.salt = vec![0u8; 16];
        assert!(validate_stored_params(&zero_salt).is_err());
    }

    #[test]
    fn recommend_params_never_exceeds_default() {
        // A generous budget on a fast host should land on the default
        // profile (the first entry in PROFILES). The function must not
        // invent a profile stronger than `default_params` regardless
        // of host speed; that's the upper bound for any account ever
        // stored.
        let recommended = recommend_params_for_throughput(1, 60_000);
        let defaults = default_params();
        assert!(recommended.memory_kib <= defaults.memory_kib);
        assert!(recommended.time_cost <= defaults.time_cost);
        assert_eq!(recommended.algorithm, defaults.algorithm);
        assert_eq!(recommended.parallelism, 1);
        assert_eq!(recommended.output_len, 32);
        assert_eq!(recommended.salt.len(), 16);
    }

    #[test]
    fn recommend_params_floors_at_min_memory() {
        // A device so slow the probe took longer than the budget. The
        // floor is 19 MiB / t=2; recommend must never go below.
        let recommended = recommend_params_for_throughput(10_000, 100);
        assert_eq!(recommended.memory_kib, MIN_RECOMMENDED_MEMORY_KIB);
        assert_eq!(recommended.time_cost, MIN_RECOMMENDED_TIME_COST);
    }

    #[test]
    fn recommend_params_picks_mid_profile_when_budget_is_tight() {
        // probe took 100ms at 8 MiB / t=1 (8192 units). A 64 MiB / t=2
        // profile (131072 units) would extrapolate to ~1600 ms; with
        // a 1500 ms budget that doesn't fit, but 64 MiB / t=1 at 800
        // ms does. The scorer should pick the latter.
        let recommended = recommend_params_for_throughput(100, 1500);
        assert_eq!(recommended.memory_kib, 64 * 1024);
        assert_eq!(recommended.time_cost, 1);
    }

    #[test]
    fn recommend_params_fresh_salt_each_call() {
        let a = recommend_params_for_throughput(50, 60_000);
        let b = recommend_params_for_throughput(50, 60_000);
        assert_ne!(a.salt, b.salt);
    }

    #[test]
    fn detects_weaker_params_for_upgrade() {
        let weak = fast_params();
        assert!(needs_upgrade(&weak));
        let upgraded = upgraded_params(&weak).unwrap();
        assert_eq!(upgraded.memory_kib, 64 * 1024);

        let current = default_params();
        assert!(!needs_upgrade(&current));
        assert!(upgraded_params(&current).is_none());
    }
}
