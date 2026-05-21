//! Hash primitives used by the secure log.
//!
//! The hash algorithm is frozen at SHA-256 for version 1 of the WIT
//! contract. Changing it is a format version bump.

use sha2::{Digest, Sha256};

/// Length of a SHA-256 digest in bytes.
pub const HASH_LEN: usize = 32;

/// A SHA-256 digest.
pub type EntryDigest = [u8; HASH_LEN];

/// The all-zero digest used as the previous-entry hash for the genesis
/// entry of a stream, and as the previous-checkpoint hash for the
/// first segment.
pub const ZERO_HASH: EntryDigest = [0u8; HASH_LEN];

/// Compute a SHA-256 digest over the given bytes.
pub fn sha256(bytes: &[u8]) -> EntryDigest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut digest = [0u8; HASH_LEN];
    digest.copy_from_slice(&out);
    digest
}

/// Format a digest as lowercase hex, for diagnostics and CLI output.
pub fn hex(digest: &EntryDigest) -> String {
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_vector() {
        // RFC 6234 test vector for SHA-256 of the empty string.
        let h = sha256(b"");
        assert_eq!(
            hex(&h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc_vector() {
        let h = sha256(b"abc");
        assert_eq!(
            hex(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn zero_hash_constant() {
        assert!(ZERO_HASH.iter().all(|&b| b == 0));
        assert_eq!(ZERO_HASH.len(), HASH_LEN);
    }
}
