use soroban_sdk::{auth::Context, crypto::Hash, BytesN, Env, Vec};

use crate::{crypto, error::SmartWalletError, nonce, storage, types::SignaturePayload};

/// Custom account `__check_auth` implementation.
///
/// Soroban calls this function when another contract invokes `require_auth`
/// for an address that resolves to this smart wallet. It is the on-chain
/// equivalent of "verify the user's biometric signature before executing
/// the requested operation".
///
/// # Protocol
/// 0. Verify that `signature_payload` matches `signed.operation_hash`.
/// 1. Look up the credential's public key by `credential_id`.
/// 2. Validate and atomically consume the nonce (replay protection).
/// 3. Reconstruct the payload hash (`SHA-256(nonce_le || operation_hash)`).
/// 4. Call the native `secp256r1_verify` host function.
/// 5. Bump TTLs so the wallet stays alive.
///
/// Returns `Ok(())` on success or a [`SmartWalletError`] on any failure,
/// which causes the host to revert the entire transaction.
pub fn check_auth(
    env: &Env,
    signature_payload: &Hash<32>,
    auth_payload: &AuthPayload,
    _auth_context: &Vec<Context>,
) -> Result<(), SmartWalletError> {
    // ── 0. Verify operation hash matches host authorization payload ──────────
    let host_op_hash: BytesN<32> = signature_payload.to_bytes();
    if host_op_hash != auth_payload.signed.operation_hash {
        return Err(SmartWalletError::InvalidOperationHash);
    }

    // ── 1. Look up the registered credential ─────────────────────────────────
    let credential = storage::load_credential(env, &auth_payload.credential_id)
        .ok_or(SmartWalletError::CredentialNotFound)?;

    // ── 2. Consume nonce (validates and increments atomically) ────────────────
    nonce::consume_nonce(env, auth_payload.signed.nonce)?;

    // ── 3. Reconstruct payload hash ───────────────────────────────────────────
    let payload_hash = crypto::hash_payload(
        env,
        auth_payload.signed.nonce,
        &auth_payload.signed.operation_hash,
    );

    // ── 4. Verify secp256r1 signature ─────────────────────────────────────────
    crypto::verify_secp256r1(
        env,
        &credential.public_key,
        &payload_hash,
        &auth_payload.signature,
    )?;

    // ── 5. Bump TTLs so the wallet stays alive ────────────────────────────────
    storage::bump_credential_ttl(env, &auth_payload.credential_id);
    storage::bump_instance_ttl(env);

    Ok(())
}

// ── AuthPayload type ──────────────────────────────────────────────────────────

use soroban_sdk::contracttype;

/// The structured bytes the TypeScript SDK encodes and attaches to every
/// sponsored transaction as the `signature_payload` argument.
///
/// Layout:
/// ```text
/// AuthPayload {
///   credential_id : BytesN<16>      // which passkey signed this tx
///   signed        : SignaturePayload // the data that was signed
///   signature     : BytesN<64>      // secp256r1 compact sig (r || s)
/// }
/// ```
#[contracttype]
#[derive(Clone)]
pub struct AuthPayload {
    /// The 16-byte CBOR credential ID identifying which registered passkey
    /// produced this signature.
    pub credential_id: BytesN<16>,
    /// The payload the device enclave signed.
    pub signed: SignaturePayload,
    /// The secp256r1 signature (r || s, 32 bytes each, low-s normalised).
    pub signature: BytesN<64>,
}
