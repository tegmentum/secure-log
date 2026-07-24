//! Pluggable canonical encoders.
//!
//! Mirrors the WIT `encoder` interface. The trait produces the exact
//! byte sequence that is hashed into the entry chain. Any two encoders
//! with identical `name()` MUST produce identical output for identical
//! inputs, forever — this is the stability guarantee a verifier relies
//! on to reconstruct entry hashes from stored fields.
//!
//! [`CborEncoder`] is the default, producing deterministic CBOR
//! (RFC 8949 §4.2.1) with byte-string encoding for hash and payload
//! fields. The encoder name is `"cbor"`.

use ciborium::value::Value;

use super::model::{CheckpointFields, EntryFields};

/// Stable identifier for the default CBOR encoder.
///
/// Matches the string returned by [`CborEncoder::name`] and stored in
/// every entry's `payload_encoding` column.
pub const ENCODER_CBOR: &str = "cbor";

/// A canonical encoder for secure log entries and checkpoints.
///
/// Implementations must be deterministic and stable over time. A
/// verifier re-encoding an entry's fields must get the same bytes as
/// the original writer, byte-for-byte.
///
/// The trait is 1:1 with the `encoder` interface in
/// `wit/secure-log.wit`. A WASM component implementing that interface
/// can be wrapped into this trait via a shim (future work).
pub trait CanonicalEncoder: Send + Sync {
    /// Encode an entry to its canonical byte form.
    fn encode_entry(&self, fields: &EntryFields) -> Vec<u8>;

    /// Encode a checkpoint to its canonical byte form.
    fn encode_checkpoint(&self, fields: &CheckpointFields) -> Vec<u8>;

    /// Stable identifier for this encoder.
    fn name(&self) -> &'static str;
}

/// Default canonical encoder: deterministic CBOR.
///
/// This encoder produces output compliant with RFC 8949 §4.2.1
/// (Core Deterministic Encoding Requirements):
///
/// - Integers use the shortest form that can hold the value.
/// - Major types are emitted in a fixed order (the field order below).
/// - Byte strings are CBOR major type 2, not arrays of u8.
/// - No indefinite-length items, tags, floats, or CBOR simple values.
///
/// Fields are laid out as a CBOR array (major type 4), not a map.
/// Array order is defined by this encoder and is part of the
/// versioned contract — changing the order is a format version bump.
pub struct CborEncoder;

impl CborEncoder {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CborEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl CanonicalEncoder for CborEncoder {
    fn encode_entry(&self, fields: &EntryFields) -> Vec<u8> {
        // Fixed field order: version, stream_id, session_id, boot_id,
        // seqno, timestamp, event_type, severity, producer,
        // payload_encoding, payload, prev_entry_hash.
        let value = Value::Array(vec![
            Value::Integer(fields.version.into()),
            Value::Text(fields.stream_id.clone()),
            Value::Text(fields.session_id.clone()),
            Value::Text(fields.boot_id.clone()),
            Value::Integer(fields.seqno.into()),
            Value::Text(fields.timestamp_rfc3339.clone()),
            Value::Text(fields.event_type.clone()),
            // Emit the severity as CBOR major type 3 (text string) so
            // the bytes are identical to what the pre-enum encoder
            // produced when callers passed `severity: String`. The
            // stable spelling is `Severity::as_str()` — see the model
            // module for the mapping.
            Value::Text(fields.severity.as_str().to_string()),
            Value::Text(fields.producer.clone()),
            Value::Text(fields.payload_encoding.clone()),
            Value::Bytes(fields.payload.clone()),
            Value::Bytes(fields.prev_entry_hash.clone()),
        ]);
        let mut buf = Vec::with_capacity(256);
        ciborium::ser::into_writer(&value, &mut buf)
            .expect("cbor encoding of entry fields cannot fail on Vec writer");
        buf
    }

    fn encode_checkpoint(&self, fields: &CheckpointFields) -> Vec<u8> {
        let value = Value::Array(vec![
            Value::Integer(fields.version.into()),
            Value::Text(fields.stream_id.clone()),
            Value::Integer(fields.segment_id.into()),
            Value::Integer(fields.seq_start.into()),
            Value::Integer(fields.seq_end.into()),
            Value::Bytes(fields.merkle_root.clone()),
            Value::Bytes(fields.last_entry_hash.clone()),
            Value::Bytes(fields.prev_checkpoint_hash.clone()),
            Value::Text(fields.boot_id.clone()),
            Value::Text(fields.session_id.clone()),
            Value::Bytes(fields.policy_hash.clone()),
            Value::Text(fields.timestamp_rfc3339.clone()),
        ]);
        let mut buf = Vec::with_capacity(256);
        ciborium::ser::into_writer(&value, &mut buf)
            .expect("cbor encoding of checkpoint fields cannot fail on Vec writer");
        buf
    }

    fn name(&self) -> &'static str {
        ENCODER_CBOR
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::ZERO_HASH;
    use crate::model::{Severity, ENTRY_VERSION};

    fn sample_entry() -> EntryFields {
        EntryFields {
            version: ENTRY_VERSION,
            stream_id: "default".into(),
            session_id: "sess-1".into(),
            boot_id: "boot-1".into(),
            seqno: 0,
            timestamp_rfc3339: "2026-04-10T00:00:00Z".into(),
            event_type: "test.event".into(),
            severity: Severity::Info,
            producer: "unit-test".into(),
            payload_encoding: "cbor".into(),
            payload: b"hello".to_vec(),
            prev_entry_hash: ZERO_HASH.to_vec(),
        }
    }

    #[test]
    fn cbor_encoder_is_deterministic() {
        let enc = CborEncoder::new();
        let a = enc.encode_entry(&sample_entry());
        let b = enc.encode_entry(&sample_entry());
        assert_eq!(a, b, "encoder must be deterministic");
    }

    #[test]
    fn cbor_encoder_name_is_stable() {
        assert_eq!(CborEncoder::new().name(), "cbor");
        assert_eq!(CborEncoder::new().name(), ENCODER_CBOR);
    }

    #[test]
    fn encoding_is_sensitive_to_field_changes() {
        let enc = CborEncoder::new();
        let e1 = sample_entry();
        let mut e2 = e1.clone();
        e2.seqno += 1;
        assert_ne!(enc.encode_entry(&e1), enc.encode_entry(&e2));

        let mut e3 = e1.clone();
        e3.payload = b"other".to_vec();
        assert_ne!(enc.encode_entry(&e1), enc.encode_entry(&e3));

        let mut e4 = e1.clone();
        e4.event_type = "changed".into();
        assert_ne!(enc.encode_entry(&e1), enc.encode_entry(&e4));
    }

    #[test]
    fn encoding_preserves_byte_strings_not_arrays() {
        // RFC 8949: a major type 2 byte string starts with 0x40..0x5b
        // (header byte) for lengths 0..23, or 0x58 followed by length
        // byte for lengths 24..255. If we accidentally encoded payload
        // as an array of u8s (major type 4, 0x80..), verification
        // costs would balloon and parsers would break — catch it here.
        let enc = CborEncoder::new();
        let bytes = enc.encode_entry(&sample_entry());
        // The payload is 5 bytes ("hello"), so its canonical CBOR
        // header is 0x45 (major type 2, short length 5). Grep for it.
        let found = bytes
            .windows(6)
            .any(|w| w == [0x45, b'h', b'e', b'l', b'l', b'o']);
        assert!(
            found,
            "expected byte-string header 0x45 before payload, got {:02x?}",
            bytes
        );
    }

    #[test]
    fn severity_encodes_as_lowercase_text_string() {
        // Wire-format regression guard: the canonical CBOR must be
        // byte-identical to what the pre-enum encoder produced when
        // callers passed `severity: "info".to_string()`. If this
        // assertion ever fails, a stored entry's chain hash would
        // stop reproducing — the on-disk bytes must not change even
        // though the Rust type went from `String` to `Severity`.
        //
        // The "string era" bytes are reconstructed here from first
        // principles rather than baked in: build the same CBOR array
        // but with a plain text severity, and compare against what
        // the current encoder emits for the sample entry.
        use ciborium::value::Value;
        let enc = CborEncoder::new();
        let bytes_enum = enc.encode_entry(&sample_entry());

        let string_era_value = Value::Array(vec![
            Value::Integer(ENTRY_VERSION.into()),
            Value::Text("default".into()),
            Value::Text("sess-1".into()),
            Value::Text("boot-1".into()),
            Value::Integer(0u64.into()),
            Value::Text("2026-04-10T00:00:00Z".into()),
            Value::Text("test.event".into()),
            Value::Text("info".into()),
            Value::Text("unit-test".into()),
            Value::Text("cbor".into()),
            Value::Bytes(b"hello".to_vec()),
            Value::Bytes(ZERO_HASH.to_vec()),
        ]);
        let mut string_era_bytes = Vec::new();
        ciborium::ser::into_writer(&string_era_value, &mut string_era_bytes)
            .expect("cbor encoding cannot fail on Vec writer");

        assert_eq!(
            bytes_enum, string_era_bytes,
            "Severity::Info must encode to identical CBOR bytes as the free-form \
             string \"info\" that the pre-enum encoder produced"
        );
    }

    #[test]
    fn every_severity_variant_encodes_to_its_lowercase_name() {
        // Sanity-check every variant so the wire-format guarantee is
        // symmetric across the enum, not just for `info`.
        let enc = CborEncoder::new();
        for (variant, expected) in [
            (Severity::Emergency, "emergency"),
            (Severity::Alert, "alert"),
            (Severity::Critical, "critical"),
            (Severity::Error, "error"),
            (Severity::Warning, "warning"),
            (Severity::Notice, "notice"),
            (Severity::Info, "info"),
            (Severity::Debug, "debug"),
        ] {
            let mut e = sample_entry();
            e.severity = variant;
            let bytes = enc.encode_entry(&e);
            // Find the expected text-string header + body somewhere
            // in the encoded array. CBOR major type 3 (text string)
            // header for a short string of length n is 0x60 | n.
            let hdr = 0x60u8 | (expected.len() as u8);
            let mut needle = Vec::with_capacity(1 + expected.len());
            needle.push(hdr);
            needle.extend_from_slice(expected.as_bytes());
            assert!(
                bytes.windows(needle.len()).any(|w| w == needle),
                "severity {:?} should embed CBOR text {:?} in the entry bytes",
                variant,
                expected
            );
        }
    }

    #[test]
    fn checkpoint_encoding_is_deterministic() {
        let cp = CheckpointFields {
            version: 1,
            stream_id: "default".into(),
            segment_id: 1,
            seq_start: 0,
            seq_end: 9,
            merkle_root: ZERO_HASH.to_vec(),
            last_entry_hash: ZERO_HASH.to_vec(),
            prev_checkpoint_hash: ZERO_HASH.to_vec(),
            boot_id: "boot-1".into(),
            session_id: "sess-1".into(),
            policy_hash: vec![0u8; 32],
            timestamp_rfc3339: "2026-04-10T00:00:00Z".into(),
        };
        let enc = CborEncoder::new();
        assert_eq!(enc.encode_checkpoint(&cp), enc.encode_checkpoint(&cp));
    }
}
