//! secure-log core, packaged as a WASI Preview 2 component.
//!
//! Imports `secure-log:log/store` for persistence and exports
//! `secure-log:log/{encoder,log}`. All integrity logic (hash chain,
//! Merkle sealing, inclusion proofs) lives in the `secure-log` core
//! crate; this component is a thin adapter:
//!
//! - [`ImportedStore`] implements the core `SecureLogStore` trait by
//!   delegating to the imported `store` interface.
//! - The exported `log` interface delegates to a [`NativeSecureLog`]
//!   built over `ImportedStore` + `CborEncoder`.
//! - The exported `encoder` interface delegates to `CborEncoder`.

#[allow(warnings)]
mod bindings;

use std::cell::RefCell;

use secure_log::{
    CanonicalEncoder, CborEncoder, CheckpointSigner, NativeSecureLog, SecureLog, SecureLogStore,
    SignerError, HASH_LEN,
};

use bindings::exports::secure_log::log::checkpoint;
use bindings::exports::secure_log::log::encoder::{
    self, CheckpointFields as WCheckpointFields, EntryFields as WEntryFields,
};
use bindings::exports::secure_log::log::log::{
    self, AppendResult as WAppendResult, InclusionProof as WInclusionProof,
    ProofStep as WProofStep, SegmentInfo as WSegmentInfo,
};
// Imported keystore: the signing key lives in whatever provider is
// composed in; only the handle + public key cross this boundary.
use bindings::keys::keystore::signer as ksigner;
use bindings::secure_log::log::store as wstore;

struct Component;

// ---------------------------------------------------------------------
// Per-instance NativeSecureLog. wasip2 is single-threaded, so a
// thread-local is a safe singleton with one session id per component
// instance.
// ---------------------------------------------------------------------

thread_local! {
    static LOG: RefCell<Option<NativeSecureLog>> = const { RefCell::new(None) };
}

fn with_log<R>(f: impl FnOnce(&NativeSecureLog) -> R) -> R {
    LOG.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            let store: Box<dyn SecureLogStore> = Box::new(ImportedStore);
            let encoder: Box<dyn CanonicalEncoder> = Box::new(CborEncoder::new());
            *opt = Some(NativeSecureLog::new(store, encoder));
        }
        f(opt.as_ref().expect("initialized above"))
    })
}

// ---------------------------------------------------------------------
// Hash conversions.
// ---------------------------------------------------------------------

fn digest_from_vec(v: Vec<u8>) -> Result<[u8; HASH_LEN], String> {
    v.try_into().map_err(|_| "hash is not 32 bytes".to_string())
}

// ---------------------------------------------------------------------
// Store-row conversions (imported `store` records <-> core rows).
// ---------------------------------------------------------------------

fn row_to_w(r: &secure_log::SecureLogRow) -> wstore::SecureLogRow {
    wstore::SecureLogRow {
        seqno: r.seqno,
        stream_id: r.stream_id.clone(),
        session_id: r.session_id.clone(),
        boot_id: r.boot_id.clone(),
        timestamp_rfc3339: r.timestamp_rfc3339.clone(),
        event_type: r.event_type.clone(),
        severity: r.severity.clone(),
        producer: r.producer.clone(),
        payload_encoding: r.payload_encoding.clone(),
        payload: r.payload.clone(),
        prev_entry_hash: r.prev_entry_hash.clone(),
        entry_hash: r.entry_hash.clone(),
    }
}

fn row_from_w(r: wstore::SecureLogRow) -> secure_log::SecureLogRow {
    secure_log::SecureLogRow {
        seqno: r.seqno,
        stream_id: r.stream_id,
        session_id: r.session_id,
        boot_id: r.boot_id,
        timestamp_rfc3339: r.timestamp_rfc3339,
        event_type: r.event_type,
        severity: r.severity,
        producer: r.producer,
        payload_encoding: r.payload_encoding,
        payload: r.payload,
        prev_entry_hash: r.prev_entry_hash,
        entry_hash: r.entry_hash,
    }
}

fn seg_to_w(r: &secure_log::SecureLogSegmentRow) -> wstore::SecureLogSegmentRow {
    wstore::SecureLogSegmentRow {
        segment_id: r.segment_id,
        stream_id: r.stream_id.clone(),
        seq_start: r.seq_start,
        seq_end: r.seq_end,
        merkle_root: r.merkle_root.clone(),
        last_entry_hash: r.last_entry_hash.clone(),
        prev_checkpoint_hash: r.prev_checkpoint_hash.clone(),
        closed_at_rfc3339: r.closed_at_rfc3339.clone(),
        signature: r.signature.clone(),
        signer_identity: r.signer_identity.clone(),
    }
}

fn seg_from_w(r: wstore::SecureLogSegmentRow) -> secure_log::SecureLogSegmentRow {
    secure_log::SecureLogSegmentRow {
        segment_id: r.segment_id,
        stream_id: r.stream_id,
        seq_start: r.seq_start,
        seq_end: r.seq_end,
        merkle_root: r.merkle_root,
        last_entry_hash: r.last_entry_hash,
        prev_checkpoint_hash: r.prev_checkpoint_hash,
        closed_at_rfc3339: r.closed_at_rfc3339,
        signature: r.signature,
        signer_identity: r.signer_identity,
    }
}

fn stream_to_w(r: &secure_log::SecureLogStreamRow) -> wstore::SecureLogStreamRow {
    wstore::SecureLogStreamRow {
        name: r.name.clone(),
        tier: r.tier.clone(),
        description: r.description.clone(),
        created_at_rfc3339: r.created_at_rfc3339.clone(),
        deprecated_at_rfc3339: r.deprecated_at_rfc3339.clone(),
    }
}

fn stream_from_w(r: wstore::SecureLogStreamRow) -> secure_log::SecureLogStreamRow {
    secure_log::SecureLogStreamRow {
        name: r.name,
        tier: r.tier,
        description: r.description,
        created_at_rfc3339: r.created_at_rfc3339,
        deprecated_at_rfc3339: r.deprecated_at_rfc3339,
    }
}

fn witness_to_w(r: &secure_log::WitnessLogRow) -> wstore::WitnessLogRow {
    wstore::WitnessLogRow {
        id: r.id,
        stream_id: r.stream_id.clone(),
        segment_id: r.segment_id,
        seq_start: r.seq_start,
        seq_end: r.seq_end,
        checkpoint_hash_hex: r.checkpoint_hash_hex.clone(),
        signature_hex: r.signature_hex.clone(),
        signer_identity: r.signer_identity.clone(),
        received_at_rfc3339: r.received_at_rfc3339.clone(),
    }
}

fn witness_from_w(r: wstore::WitnessLogRow) -> secure_log::WitnessLogRow {
    secure_log::WitnessLogRow {
        id: r.id,
        stream_id: r.stream_id,
        segment_id: r.segment_id,
        seq_start: r.seq_start,
        seq_end: r.seq_end,
        checkpoint_hash_hex: r.checkpoint_hash_hex,
        signature_hex: r.signature_hex,
        signer_identity: r.signer_identity,
        received_at_rfc3339: r.received_at_rfc3339,
    }
}

// ---------------------------------------------------------------------
// ImportedStore: SecureLogStore over the imported `store` interface.
// ---------------------------------------------------------------------

struct ImportedStore;

fn ae(e: String) -> anyhow::Error {
    anyhow::anyhow!(e)
}

impl SecureLogStore for ImportedStore {
    fn secure_log_insert(&self, row: &secure_log::SecureLogRow) -> anyhow::Result<u64> {
        wstore::secure_log_insert(&row_to_w(row)).map_err(ae)
    }

    fn secure_log_global_head(&self) -> anyhow::Result<Option<u64>> {
        wstore::secure_log_global_head().map_err(ae)
    }

    fn secure_log_get(&self, seqno: u64) -> anyhow::Result<Option<secure_log::SecureLogRow>> {
        Ok(wstore::secure_log_get(seqno).map_err(ae)?.map(row_from_w))
    }

    fn secure_log_range(
        &self,
        stream_id: &str,
        from: u64,
        to: u64,
    ) -> anyhow::Result<Vec<secure_log::SecureLogRow>> {
        Ok(wstore::secure_log_range(stream_id, from, to)
            .map_err(ae)?
            .into_iter()
            .map(row_from_w)
            .collect())
    }

    fn secure_log_head(&self, stream_id: &str) -> anyhow::Result<Option<u64>> {
        wstore::secure_log_head(stream_id).map_err(ae)
    }

    fn secure_log_last(&self, stream_id: &str) -> anyhow::Result<Option<secure_log::SecureLogRow>> {
        Ok(wstore::secure_log_last(stream_id)
            .map_err(ae)?
            .map(row_from_w))
    }

    fn secure_log_segment_insert(
        &self,
        row: &secure_log::SecureLogSegmentRow,
        entries: &[(u64, u64)],
    ) -> anyhow::Result<u64> {
        wstore::secure_log_segment_insert(&seg_to_w(row), entries).map_err(ae)
    }

    fn secure_log_segment_get(
        &self,
        segment_id: u64,
    ) -> anyhow::Result<Option<secure_log::SecureLogSegmentRow>> {
        Ok(wstore::secure_log_segment_get(segment_id)
            .map_err(ae)?
            .map(seg_from_w))
    }

    fn secure_log_segments_list(
        &self,
        stream_id: &str,
    ) -> anyhow::Result<Vec<secure_log::SecureLogSegmentRow>> {
        Ok(wstore::secure_log_segments_list(stream_id)
            .map_err(ae)?
            .into_iter()
            .map(seg_from_w)
            .collect())
    }

    fn secure_log_segment_last_seqno(&self, stream_id: &str) -> anyhow::Result<Option<u64>> {
        wstore::secure_log_segment_last_seqno(stream_id).map_err(ae)
    }

    fn secure_log_segment_entry_seqnos(&self, segment_id: u64) -> anyhow::Result<Vec<u64>> {
        wstore::secure_log_segment_entry_seqnos(segment_id).map_err(ae)
    }

    fn secure_log_segment_for_seqno(&self, seqno: u64) -> anyhow::Result<Option<u64>> {
        wstore::secure_log_segment_for_seqno(seqno).map_err(ae)
    }

    fn secure_log_segment_set_signature(
        &self,
        segment_id: u64,
        signature: &[u8],
        signer_identity: &str,
    ) -> anyhow::Result<()> {
        wstore::secure_log_segment_set_signature(segment_id, signature, signer_identity).map_err(ae)
    }

    fn witness_log_insert(&self, row: &secure_log::WitnessLogRow) -> anyhow::Result<u64> {
        wstore::witness_log_insert(&witness_to_w(row)).map_err(ae)
    }

    fn witness_log_latest(
        &self,
        stream_id: &str,
    ) -> anyhow::Result<Option<secure_log::WitnessLogRow>> {
        Ok(wstore::witness_log_latest(stream_id)
            .map_err(ae)?
            .map(witness_from_w))
    }

    fn witness_log_list(&self, stream_id: &str) -> anyhow::Result<Vec<secure_log::WitnessLogRow>> {
        Ok(wstore::witness_log_list(stream_id)
            .map_err(ae)?
            .into_iter()
            .map(witness_from_w)
            .collect())
    }

    fn witness_log_stream_ids(&self) -> anyhow::Result<Vec<String>> {
        wstore::witness_log_stream_ids().map_err(ae)
    }

    fn witness_log_gc(
        &self,
        stream_id: Option<&str>,
        keep_latest: Option<usize>,
        older_than_rfc3339: Option<&str>,
    ) -> anyhow::Result<usize> {
        let n =
            wstore::witness_log_gc(stream_id, keep_latest.map(|k| k as u32), older_than_rfc3339)
                .map_err(ae)?;
        Ok(n as usize)
    }

    fn secure_log_stream_upsert(&self, row: &secure_log::SecureLogStreamRow) -> anyhow::Result<()> {
        wstore::secure_log_stream_upsert(&stream_to_w(row)).map_err(ae)
    }

    fn secure_log_stream_get(
        &self,
        name: &str,
    ) -> anyhow::Result<Option<secure_log::SecureLogStreamRow>> {
        Ok(wstore::secure_log_stream_get(name)
            .map_err(ae)?
            .map(stream_from_w))
    }

    fn secure_log_stream_list(&self) -> anyhow::Result<Vec<secure_log::SecureLogStreamRow>> {
        Ok(wstore::secure_log_stream_list()
            .map_err(ae)?
            .into_iter()
            .map(stream_from_w)
            .collect())
    }

    fn secure_log_stream_set_tier(&self, name: &str, tier: &str) -> anyhow::Result<()> {
        wstore::secure_log_stream_set_tier(name, tier).map_err(ae)
    }

    fn secure_log_stream_deprecate(
        &self,
        name: &str,
        deprecated_at_rfc3339: &str,
    ) -> anyhow::Result<()> {
        wstore::secure_log_stream_deprecate(name, deprecated_at_rfc3339).map_err(ae)
    }
}

// ---------------------------------------------------------------------
// Export-record conversions (core types -> exported WIT records).
// ---------------------------------------------------------------------

fn entry_to_w(f: secure_log::EntryFields) -> WEntryFields {
    WEntryFields {
        version: f.version,
        stream_id: f.stream_id,
        session_id: f.session_id,
        boot_id: f.boot_id,
        seqno: f.seqno,
        timestamp_rfc3339: f.timestamp_rfc3339,
        event_type: f.event_type,
        severity: f.severity,
        producer: f.producer,
        payload_encoding: f.payload_encoding,
        payload: f.payload,
        prev_entry_hash: f.prev_entry_hash,
    }
}

fn entry_from_w(f: WEntryFields) -> secure_log::EntryFields {
    secure_log::EntryFields {
        version: f.version,
        stream_id: f.stream_id,
        session_id: f.session_id,
        boot_id: f.boot_id,
        seqno: f.seqno,
        timestamp_rfc3339: f.timestamp_rfc3339,
        event_type: f.event_type,
        severity: f.severity,
        producer: f.producer,
        payload_encoding: f.payload_encoding,
        payload: f.payload,
        prev_entry_hash: f.prev_entry_hash,
    }
}

fn checkpoint_from_w(f: WCheckpointFields) -> secure_log::CheckpointFields {
    secure_log::CheckpointFields {
        version: f.version,
        stream_id: f.stream_id,
        segment_id: f.segment_id,
        seq_start: f.seq_start,
        seq_end: f.seq_end,
        merkle_root: f.merkle_root,
        last_entry_hash: f.last_entry_hash,
        prev_checkpoint_hash: f.prev_checkpoint_hash,
        boot_id: f.boot_id,
        session_id: f.session_id,
        policy_hash: f.policy_hash,
        timestamp_rfc3339: f.timestamp_rfc3339,
    }
}

fn segment_info_to_w(s: secure_log::SegmentInfo) -> WSegmentInfo {
    WSegmentInfo {
        segment_id: s.segment_id,
        stream_id: s.stream_id,
        seq_start: s.seq_start,
        seq_end: s.seq_end,
        merkle_root: s.merkle_root.to_vec(),
        last_entry_hash: s.last_entry_hash.to_vec(),
        prev_checkpoint_hash: s.prev_checkpoint_hash.to_vec(),
        closed_at_rfc3339: s.closed_at_rfc3339,
        signature: if s.signature.is_empty() {
            None
        } else {
            Some(s.signature)
        },
        signer_identity: s.signer_identity,
    }
}

fn proof_to_w(p: secure_log::InclusionProof) -> WInclusionProof {
    WInclusionProof {
        seqno: p.seqno,
        entry_hash: p.entry_hash.to_vec(),
        segment_id: p.segment_id,
        merkle_root: p.merkle_root.to_vec(),
        path: p
            .path
            .into_iter()
            .map(|step| WProofStep {
                sibling_hash: step.sibling_hash.to_vec(),
                right: step.right,
            })
            .collect(),
    }
}

fn proof_from_w(p: WInclusionProof) -> Result<secure_log::InclusionProof, String> {
    let mut path = Vec::with_capacity(p.path.len());
    for step in p.path {
        path.push(secure_log::ProofStep {
            sibling_hash: digest_from_vec(step.sibling_hash)?,
            right: step.right,
        });
    }
    Ok(secure_log::InclusionProof {
        seqno: p.seqno,
        entry_hash: digest_from_vec(p.entry_hash)?,
        segment_id: p.segment_id,
        merkle_root: digest_from_vec(p.merkle_root)?,
        path,
    })
}

// ---------------------------------------------------------------------
// Exported `encoder` interface.
// ---------------------------------------------------------------------

impl encoder::Guest for Component {
    fn encode_entry(fields: WEntryFields) -> Vec<u8> {
        CborEncoder::new().encode_entry(&entry_from_w(fields))
    }

    fn encode_checkpoint(fields: WCheckpointFields) -> Vec<u8> {
        CborEncoder::new().encode_checkpoint(&checkpoint_from_w(fields))
    }

    fn name() -> String {
        CborEncoder::new().name().to_string()
    }
}

// ---------------------------------------------------------------------
// Exported `log` interface.
// ---------------------------------------------------------------------

impl log::Guest for Component {
    fn open(config: String) -> Result<(), String> {
        wstore::init(&config)
    }

    fn append(
        stream_id: String,
        event_type: String,
        severity: String,
        producer: String,
        payload: Vec<u8>,
    ) -> Result<WAppendResult, String> {
        with_log(|log| log.append(&stream_id, &event_type, &severity, &producer, &payload))
            .map(|r| WAppendResult {
                seqno: r.seqno,
                entry_hash: r.entry_hash.to_vec(),
            })
            .map_err(|e| e.to_string())
    }

    fn read(seqno: u64) -> Result<WEntryFields, String> {
        with_log(|log| log.read(seqno))
            .map(entry_to_w)
            .map_err(|e| e.to_string())
    }

    fn head(stream_id: String) -> Result<Option<u64>, String> {
        with_log(|log| log.head(&stream_id)).map_err(|e| e.to_string())
    }

    fn verify_chain(stream_id: String, from_seqno: u64, to_seqno: u64) -> Result<(), String> {
        with_log(|log| log.verify_chain(&stream_id, from_seqno, to_seqno))
            .map_err(|e| e.to_string())
    }

    fn close_segment(stream_id: String) -> Result<WSegmentInfo, String> {
        with_log(|log| log.close_segment(&stream_id))
            .map(segment_info_to_w)
            .map_err(|e| e.to_string())
    }

    fn list_segments(stream_id: String) -> Vec<WSegmentInfo> {
        with_log(|log| log.list_segments(&stream_id))
            .map(|v| v.into_iter().map(segment_info_to_w).collect())
            .unwrap_or_default()
    }

    fn read_segment(segment_id: u64) -> Result<WSegmentInfo, String> {
        with_log(|log| log.read_segment(segment_id))
            .map(segment_info_to_w)
            .map_err(|e| e.to_string())
    }

    fn build_inclusion_proof(seqno: u64) -> Result<WInclusionProof, String> {
        with_log(|log| log.inclusion_proof(seqno))
            .map(proof_to_w)
            .map_err(|e| e.to_string())
    }

    fn verify_inclusion_proof(
        proof: WInclusionProof,
        expected_root: Vec<u8>,
    ) -> Result<(), String> {
        let core_proof = proof_from_w(proof)?;
        let root = digest_from_vec(expected_root)?;
        secure_log::verify_inclusion_proof(&core_proof, &root).map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------
// In-graph checkpoint signing.
//
// `ComponentSigner` adapts the imported `keys:keystore/signer` to the
// core `CheckpointSigner` trait. Signing is delegated to the keystore
// (the key never crosses the boundary); verification is done here,
// dispatching on the key's algorithm over its public key.
// ---------------------------------------------------------------------

struct ComponentSigner;

/// A resolved keystore key: the handle plus cached public material.
struct CachedKey {
    key: ksigner::Key,
    algorithm: String,
    public_key: Vec<u8>,
}

thread_local! {
    // label -> resolved key. Resolved once per label per instance: some
    // keystore backends (e.g. the softhsm adapter) run a login/provision
    // ceremony in `get-key` that is not idempotent, so a fresh `get-key`
    // per sign and per verify would fail.
    static KEYS: RefCell<std::collections::HashMap<String, CachedKey>> =
        RefCell::new(std::collections::HashMap::new());
}

fn map_ks(e: ksigner::Error) -> SignerError {
    match e {
        ksigner::Error::KeyNotFound(s) => SignerError::UnknownIdentity(s),
        ksigner::Error::UnsupportedAlgorithm(s) => {
            SignerError::SignFailed(format!("unsupported algorithm: {s}"))
        }
        ksigner::Error::AccessDenied(s) => SignerError::SignFailed(format!("access denied: {s}")),
        ksigner::Error::Backend(s) => SignerError::Storage(s),
    }
}

/// Run `f` against the (cached) key resolved for `label`.
fn with_key<R>(label: &str, f: impl FnOnce(&CachedKey) -> R) -> Result<R, SignerError> {
    KEYS.with(|cell| {
        let mut keys = cell.borrow_mut();
        if !keys.contains_key(label) {
            let key = ksigner::get_key(label).map_err(map_ks)?;
            let algorithm = key.algorithm();
            let public_key = key.public_key();
            keys.insert(
                label.to_string(),
                CachedKey {
                    key,
                    algorithm,
                    public_key,
                },
            );
        }
        Ok(f(keys.get(label).expect("inserted above")))
    })
}

impl CheckpointSigner for ComponentSigner {
    fn sign_checkpoint(
        &self,
        identity_name: &str,
        message: &[u8],
    ) -> Result<(Vec<u8>, String), SignerError> {
        let signature = with_key(identity_name, |ck| ck.key.sign(message))?.map_err(map_ks)?;
        Ok((signature, identity_name.to_string()))
    }

    fn verify_checkpoint(
        &self,
        signer_identity: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, SignerError> {
        let (algorithm, public_key) = with_key(signer_identity, |ck| {
            (ck.algorithm.clone(), ck.public_key.clone())
        })?;
        verify_signature(&algorithm, &public_key, message, signature)
    }
}

/// Verify `signature` over `message` using `public_key`, dispatching on
/// the keystore's algorithm identifier. Sign and verify share the same
/// convention: ed25519 signs the message bytes (EdDSA); ecdsa-p256 and
/// rsa-pss-sha256 hash the message with SHA-256 internally.
fn verify_signature(
    algorithm: &str,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, SignerError> {
    match algorithm {
        "ed25519" => verify_ed25519(public_key, message, signature),
        "ecdsa-p256" => verify_ecdsa_p256(public_key, message, signature),
        "rsa-pss-sha256" => verify_rsa_pss_sha256(public_key, message, signature),
        other => Err(SignerError::VerifyFailed(format!(
            "unsupported algorithm '{other}'"
        ))),
    }
}

fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, SignerError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SignerError::VerifyFailed("ed25519 public key must be 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&pk)
        .map_err(|e| SignerError::VerifyFailed(format!("bad ed25519 key: {e}")))?;
    let Ok(sig) = Signature::from_slice(signature) else {
        return Ok(false);
    };
    Ok(vk.verify(message, &sig).is_ok())
}

fn verify_ecdsa_p256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, SignerError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| SignerError::VerifyFailed(format!("bad ecdsa-p256 key: {e}")))?;
    let Ok(sig) = Signature::from_slice(signature) else {
        return Ok(false);
    };
    Ok(vk.verify(message, &sig).is_ok())
}

fn verify_rsa_pss_sha256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, SignerError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;
    let pub_key = RsaPublicKey::from_pkcs1_der(public_key)
        .map_err(|e| SignerError::VerifyFailed(format!("bad rsa public key: {e}")))?;
    let vk: VerifyingKey<sha2::Sha256> = VerifyingKey::new(pub_key);
    let Ok(sig) = Signature::try_from(signature) else {
        return Ok(false);
    };
    Ok(vk.verify(message, &sig).is_ok())
}

// ---------------------------------------------------------------------
// Exported `checkpoint` interface.
// ---------------------------------------------------------------------

impl checkpoint::Guest for Component {
    fn sign_segment(identity: String, segment_id: u64) -> Result<(Vec<u8>, Vec<u8>), String> {
        with_log(|log| log.sign_segment(&ComponentSigner, &identity, segment_id))
            .map(|(hash, sig)| (hash.to_vec(), sig))
            .map_err(|e| e.to_string())
    }

    fn verify_segment_signature(segment_id: u64) -> Result<Vec<u8>, String> {
        with_log(|log| log.verify_segment_signature(&ComponentSigner, segment_id))
            .map(|hash| hash.to_vec())
            .map_err(|e| e.to_string())
    }

    fn verify_checkpoint_chain(stream_id: String) -> Result<u32, String> {
        with_log(|log| log.verify_checkpoint_chain(&ComponentSigner, &stream_id))
            .map(|n| n as u32)
            .map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------
// Exported `tegmentum:log/logger` interface — the generic log-wit
// adapter. Maps a write-only `log(entry)` call onto an audit-graded
// `secure-log:log/log.append(...)` so consumers of the generic
// contract (Python's _log_cap, Rust log-crate adapter, JS console
// redirect) get hash-chained, Merkle-sealed delivery without knowing
// secure-log's richer surface.
//
// Mapping:
//   entry.severity (enum) → SecureLog severity string ("info", "warn", …)
//   entry.category        → SecureLog stream_id (defaults to "default")
//   entry.producer        → SecureLog producer (passed through verbatim)
//   entry.message         → JSON-wrapped payload when fields are present:
//                             {"message":"...","fields":{...}}
//                           plain message bytes otherwise.
//   entry.timestamp       → consumed by Component::append impl; this
//                           tegmentum:log adapter doesn't surface it
//                           explicitly because secure-log's append
//                           uses the host's clock for audit reasons
//                           (deterministic order, no producer skew).
// ---------------------------------------------------------------------

use bindings::exports::tegmentum::log::logger as wlogger;

fn severity_to_str(s: wlogger::Severity) -> &'static str {
    match s {
        wlogger::Severity::Emergency => "emerg",
        wlogger::Severity::Alert => "alert",
        wlogger::Severity::Critical => "crit",
        wlogger::Severity::Error => "err",
        wlogger::Severity::Warning => "warning",
        wlogger::Severity::Notice => "notice",
        wlogger::Severity::Info => "info",
        wlogger::Severity::Debug => "debug",
    }
}

/// Encode the entry's payload. Plain message bytes if there are no
/// structured fields; an inline JSON object `{"message":..,"fields":..}`
/// otherwise. (The secure-log core's `append` doesn't take an
/// encoding parameter — it tags every payload uniformly per the
/// canonical encoder. Adapter consumers that need to discriminate
/// at read time should sniff the first byte / try-decode as JSON.)
fn encode_payload(message: &str, fields: &[wlogger::Field]) -> Vec<u8> {
    if fields.is_empty() {
        return message.as_bytes().to_vec();
    }
    let mut s = String::from("{\"message\":");
    json_str(&mut s, message);
    s.push_str(",\"fields\":{");
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        json_str(&mut s, &f.key);
        s.push(':');
        json_str(&mut s, &f.value);
    }
    s.push_str("}}");
    s.into_bytes()
}

fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

impl wlogger::Guest for Component {
    fn log(rec: wlogger::Entry) {
        let stream_id = if rec.category.is_empty() {
            "default".to_string()
        } else {
            rec.category
        };
        let severity = severity_to_str(rec.severity);
        let payload = encode_payload(&rec.message, &rec.fields);
        // Best-effort: a write-only logger drops on backend error.
        // Consumers that need delivery guarantees use the richer
        // secure-log:log/log.append directly and check the result.
        let _ = with_log(|log| log.append(&stream_id, "log", severity, &rec.producer, &payload));
        let _ = rec.timestamp_rfc3339; // consumed; see module-level mapping doc
    }

    fn flush() {
        // Append is synchronous in NativeSecureLog; nothing buffered to flush.
    }

    fn backend_name() -> String {
        "secure-log:v1".to_string()
    }
}

bindings::export!(Component with_types_in bindings);
