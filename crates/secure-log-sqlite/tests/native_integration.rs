//! Integration tests that exercise `NativeSecureLog` against the
//! SQLite-backed `SqliteSecureLogStore`.

use secure_log::{
    sha256, CanonicalEncoder, CborEncoder, CheckpointSigner, NativeSecureLog, SecureLog,
    SecureLogError, SecureLogStore, SecureLogStreamRow, SignerError, ZERO_HASH,
};
use secure_log_sqlite::SqliteSecureLogStore;

/// Deterministic in-test signer. The "signature" is the SHA-256 of
/// (identity_name || message), so verification is just re-signing
/// and comparing bytes.
struct MockCheckpointSigner;

impl CheckpointSigner for MockCheckpointSigner {
    fn sign_checkpoint(
        &self,
        identity_name: &str,
        message: &[u8],
    ) -> Result<(Vec<u8>, String), SignerError> {
        let mut buf = Vec::with_capacity(identity_name.len() + message.len());
        buf.extend_from_slice(identity_name.as_bytes());
        buf.extend_from_slice(message);
        let sig = sha256(&buf).to_vec();
        Ok((sig, identity_name.to_string()))
    }

    fn verify_checkpoint(
        &self,
        signer_identity: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, SignerError> {
        let (expected, _) = self.sign_checkpoint(signer_identity, message)?;
        Ok(expected == signature)
    }
}

fn new_log() -> NativeSecureLog {
    let store = Box::new(SqliteSecureLogStore::open_in_memory().unwrap());
    let encoder: Box<dyn CanonicalEncoder> = Box::new(CborEncoder::new());
    NativeSecureLog::new(store, encoder)
        .with_session_id("sess-test")
        .with_boot_id("boot-test")
}

#[test]
fn genesis_entry_has_zero_prev_hash() {
    let log = new_log();
    let r = log
        .append("default", "test.genesis", "info", "unit", b"hello")
        .unwrap();
    assert_eq!(r.seqno, 1);
    let e = log.read(1).unwrap();
    assert_eq!(e.prev_entry_hash, ZERO_HASH.to_vec());
}

#[test]
fn second_entry_chains_to_first() {
    let log = new_log();
    let a = log.append("default", "a", "info", "t", b"one").unwrap();
    let b = log.append("default", "b", "info", "t", b"two").unwrap();
    let entry_b = log.read(b.seqno).unwrap();
    assert_eq!(entry_b.prev_entry_hash, a.entry_hash.to_vec());
}

#[test]
fn chain_verifies_over_multiple_entries() {
    let log = new_log();
    for i in 0..10 {
        log.append("default", "tick", "info", "t", format!("n={}", i).as_bytes())
            .unwrap();
    }
    log.verify_chain("default", 1, 10).unwrap();
}

#[test]
fn head_tracks_latest_seqno() {
    let log = new_log();
    assert_eq!(log.head("default").unwrap(), None);
    log.append("default", "a", "info", "t", b"x").unwrap();
    log.append("default", "b", "info", "t", b"y").unwrap();
    assert_eq!(log.head("default").unwrap(), Some(2));
}

#[test]
fn verify_chain_fails_on_missing_range() {
    let log = new_log();
    let err = log.verify_chain("default", 1, 5).unwrap_err();
    assert!(matches!(err, SecureLogError::StreamNotFound(_)));
}

#[test]
fn two_streams_share_global_seqno_namespace() {
    let log = new_log();
    let a1 = log.append("stream-a", "x", "info", "t", b"1").unwrap();
    let b1 = log.append("stream-b", "x", "info", "t", b"2").unwrap();
    let a2 = log.append("stream-a", "x", "info", "t", b"3").unwrap();
    assert_eq!(a1.seqno, 1);
    assert_eq!(b1.seqno, 2);
    assert_eq!(a2.seqno, 3);
    assert_eq!(log.head("stream-a").unwrap(), Some(3));
    assert_eq!(log.head("stream-b").unwrap(), Some(2));
}

#[test]
fn per_stream_chains_link_across_global_gaps() {
    let log = new_log();
    let a1 = log.append("stream-a", "x", "info", "t", b"one").unwrap();
    let _b1 = log.append("stream-b", "x", "info", "t", b"mid").unwrap();
    log.append("stream-a", "x", "info", "t", b"two").unwrap();
    let a2 = log.read(3).unwrap();
    assert_eq!(a2.stream_id, "stream-a");
    assert_eq!(a2.prev_entry_hash, a1.entry_hash.to_vec());
    log.verify_chain("stream-a", 1, 3).unwrap();
    log.verify_chain("stream-b", 1, 3).unwrap();
}

#[test]
fn close_segment_builds_merkle_root_and_inclusion_proof_round_trips() {
    use secure_log::verify_inclusion_proof;

    let log = new_log();
    for i in 0..5 {
        log.append("default", "e", "info", "t", format!("v{}", i).as_bytes())
            .unwrap();
    }
    let seg = log.close_segment("default").unwrap();
    assert_eq!(seg.seq_start, 1);
    assert_eq!(seg.seq_end, 5);
    assert_eq!(seg.prev_checkpoint_hash, ZERO_HASH);
    assert_ne!(seg.merkle_root, ZERO_HASH);

    for seqno in 1..=5u64 {
        let proof = log.inclusion_proof(seqno).unwrap();
        assert_eq!(proof.segment_id, seg.segment_id);
        assert_eq!(proof.merkle_root, seg.merkle_root);
        verify_inclusion_proof(&proof, &seg.merkle_root).unwrap();
    }
}

#[test]
fn close_segment_chains_prev_checkpoint_to_previous_checkpoint_hash() {
    let log = new_log();
    for _ in 0..3 {
        log.append("default", "e", "info", "t", b"x").unwrap();
    }
    let seg1 = log.close_segment("default").unwrap();
    for _ in 0..3 {
        log.append("default", "e", "info", "t", b"y").unwrap();
    }
    let seg2 = log.close_segment("default").unwrap();
    assert_eq!(seg2.seq_start, seg1.seq_end + 1);
    assert_ne!(seg2.prev_checkpoint_hash, ZERO_HASH);
    let recomputed = log
        .compute_checkpoint_hash_for("default", seg1.segment_id)
        .unwrap();
    assert_eq!(seg2.prev_checkpoint_hash, recomputed);
}

#[test]
fn close_empty_segment_errors() {
    let log = new_log();
    log.append("default", "e", "info", "t", b"x").unwrap();
    log.close_segment("default").unwrap();
    let err = log.close_segment("default").unwrap_err();
    assert!(matches!(err, SecureLogError::EmptySegment(_)));
}

#[test]
fn list_segments_returns_in_order() {
    let log = new_log();
    for _ in 0..2 {
        log.append("default", "e", "info", "t", b"x").unwrap();
    }
    let a = log.close_segment("default").unwrap();
    for _ in 0..2 {
        log.append("default", "e", "info", "t", b"y").unwrap();
    }
    let b = log.close_segment("default").unwrap();
    let list = log.list_segments("default").unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].segment_id, a.segment_id);
    assert_eq!(list[1].segment_id, b.segment_id);
}

#[test]
fn sign_and_verify_checkpoint_chain_round_trips() {
    let log = new_log();
    let signer = MockCheckpointSigner;

    for _ in 0..3 {
        log.append("default", "e", "info", "t", b"x").unwrap();
    }
    let seg1 = log.close_segment("default").unwrap();
    log.sign_segment(&signer, "log-signer", seg1.segment_id)
        .unwrap();

    for _ in 0..3 {
        log.append("default", "e", "info", "t", b"y").unwrap();
    }
    let seg2 = log.close_segment("default").unwrap();
    log.sign_segment(&signer, "log-signer", seg2.segment_id)
        .unwrap();

    let n = log.verify_checkpoint_chain(&signer, "default").unwrap();
    assert_eq!(n, 2);
}

#[test]
fn head_file_is_written_on_sign() {
    use secure_log::witness::HeadFile;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let head_path = dir.path().join("heads.json");
    let store = Box::new(SqliteSecureLogStore::open_in_memory().unwrap());
    let encoder: Box<dyn CanonicalEncoder> = Box::new(CborEncoder::new());
    let log = NativeSecureLog::new(store, encoder)
        .with_session_id("sess-test")
        .with_boot_id("boot-test")
        .with_head_file(&head_path);
    let signer = MockCheckpointSigner;

    for _ in 0..3 {
        log.append("default", "e", "info", "t", b"x").unwrap();
    }
    let seg = log.close_segment("default").unwrap();
    log.sign_segment(&signer, "log-signer", seg.segment_id)
        .unwrap();

    let hf = HeadFile::load(&head_path).unwrap();
    assert_eq!(hf.records.len(), 1);
    let rec = hf.get("default").unwrap();
    assert_eq!(rec.segment_id, seg.segment_id);
    assert_eq!(rec.seq_end, 3);

    log.check_rollback(&signer, "default").unwrap();
}

#[test]
fn check_rollback_detects_missing_segment() {
    use secure_log::witness::{HeadFile, HeadRecord};
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let head_path = dir.path().join("heads.json");
    let mut hf = HeadFile::default();
    hf.version = HeadFile::VERSION;
    hf.upsert(HeadRecord {
        stream_id: "default".into(),
        segment_id: 42,
        seq_end: 100,
        checkpoint_hash_hex: "aa".repeat(32),
        updated_at_rfc3339: "2026-04-10T00:00:00Z".into(),
    });
    hf.save(&head_path).unwrap();

    let log = new_log().with_head_file(&head_path);
    let signer = MockCheckpointSigner;
    let err = log.check_rollback(&signer, "default").unwrap_err();
    assert!(matches!(err, SecureLogError::ChainBroken { .. }));
}

#[test]
fn verify_checkpoint_chain_rejects_unsigned() {
    let log = new_log();
    let signer = MockCheckpointSigner;
    for _ in 0..2 {
        log.append("default", "e", "info", "t", b"x").unwrap();
    }
    log.close_segment("default").unwrap();
    let err = log
        .verify_checkpoint_chain(&signer, "default")
        .unwrap_err();
    assert!(matches!(err, SecureLogError::Invalid(_)));
}

#[test]
fn encrypted_append_and_open_round_trip() {
    use secure_log::crypto::SecretKey;

    let store = Box::new(SqliteSecureLogStore::open_in_memory().unwrap());
    let encoder: Box<dyn CanonicalEncoder> = Box::new(CborEncoder::new());
    let master = SecretKey::new([9u8; 32]);
    let log = NativeSecureLog::new(store, encoder)
        .with_session_id("sess-test")
        .with_boot_id("boot-test")
        .with_master_key(master);

    let r = log
        .append_encrypted("default", "secret.ev", "info", "t", b"very secret")
        .unwrap();
    assert_eq!(r.seqno, 1);

    let entry = log.read(1).unwrap();
    assert_eq!(entry.payload_encoding, secure_log::crypto::AEAD_NAME);
    assert_ne!(entry.payload, b"very secret");

    let pt = log.open_payload(1).unwrap();
    assert_eq!(pt, b"very secret");

    log.verify_chain("default", 1, 1).unwrap();
}

#[test]
fn encrypted_open_fails_with_wrong_master_key() {
    use secure_log::crypto::SecretKey;

    let store = Box::new(SqliteSecureLogStore::open_in_memory().unwrap());
    let encoder: Box<dyn CanonicalEncoder> = Box::new(CborEncoder::new());
    let log = NativeSecureLog::new(store, encoder)
        .with_session_id("sess-test")
        .with_boot_id("boot-test")
        .with_master_key(SecretKey::new([1u8; 32]));

    log.append_encrypted("default", "e", "info", "t", b"msg")
        .unwrap();

    let store2 = Box::new(SqliteSecureLogStore::open_in_memory().unwrap());
    let encoder2: Box<dyn CanonicalEncoder> = Box::new(CborEncoder::new());
    let log2 = NativeSecureLog::new(store2, encoder2)
        .with_session_id("sess-test")
        .with_boot_id("boot-test")
        .with_master_key(SecretKey::new([2u8; 32]));
    let row = log.store().secure_log_get(1).unwrap().unwrap();
    log2.store().secure_log_insert(&row).unwrap();
    let err = log2.open_payload(1).unwrap_err();
    assert!(matches!(err, SecureLogError::Encoding(_)));
}

#[test]
fn highly_restricted_stream_minimizes_metadata() {
    use secure_log::crypto::{is_minimized_tag, minimize_metadata, SecretKey};

    let store = Box::new(SqliteSecureLogStore::open_in_memory().unwrap());
    store
        .secure_log_stream_upsert(&SecureLogStreamRow {
            name: "secrets".into(),
            tier: "highly-restricted".into(),
            description: None,
            created_at_rfc3339: chrono::Utc::now().to_rfc3339(),
            deprecated_at_rfc3339: None,
        })
        .unwrap();

    let encoder: Box<dyn CanonicalEncoder> = Box::new(CborEncoder::new());
    let master = SecretKey::new([23u8; 32]);
    let log = NativeSecureLog::new(store, encoder)
        .with_session_id("sess-test")
        .with_boot_id("boot-test")
        .with_master_key(master.clone());

    let r = log
        .append_encrypted("secrets", "user.login", "info", "authd", b"pw")
        .unwrap();

    let entry = log.read(r.seqno).unwrap();
    assert!(is_minimized_tag(&entry.event_type));
    assert!(is_minimized_tag(&entry.producer));
    assert!(!entry.event_type.contains("user.login"));
    assert!(!entry.producer.contains("authd"));

    let expected_event = minimize_metadata(&master, "secrets", "event_type", "user.login");
    assert_eq!(entry.event_type, expected_event);

    let plaintext = log.open_payload(r.seqno).unwrap();
    assert_eq!(plaintext, b"pw");

    log.verify_chain("secrets", 1, 1).unwrap();
}

#[test]
fn protected_stream_keeps_metadata_plaintext() {
    use secure_log::crypto::SecretKey;

    let store = Box::new(SqliteSecureLogStore::open_in_memory().unwrap());
    store
        .secure_log_stream_upsert(&SecureLogStreamRow {
            name: "protected".into(),
            tier: "protected".into(),
            description: None,
            created_at_rfc3339: chrono::Utc::now().to_rfc3339(),
            deprecated_at_rfc3339: None,
        })
        .unwrap();

    let encoder: Box<dyn CanonicalEncoder> = Box::new(CborEncoder::new());
    let log = NativeSecureLog::new(store, encoder)
        .with_session_id("sess-test")
        .with_boot_id("boot-test")
        .with_master_key(SecretKey::new([23u8; 32]));

    log.append_encrypted("protected", "user.login", "info", "authd", b"pw")
        .unwrap();
    let entry = log.read(1).unwrap();
    assert_eq!(entry.event_type, "user.login");
    assert_eq!(entry.producer, "authd");
}

#[test]
fn open_payload_passes_through_plaintext_entries() {
    let log = new_log();
    log.append("default", "e", "info", "t", b"plain").unwrap();
    let out = log.open_payload(1).unwrap();
    assert_eq!(out, b"plain");
}

#[test]
fn verify_chain_detects_content_drift_via_recompute() {
    let log = new_log();
    let r = log
        .append("default", "e", "info", "t", b"original")
        .unwrap();
    let mut fields = log.read(r.seqno).unwrap();
    fields.payload = b"tampered".to_vec();
    let recomputed = sha256(&log.encoder().encode_entry(&fields));
    assert_ne!(recomputed, r.entry_hash);
}
