use soroban_sdk::{auth::Context, BytesN, Env, Vec};

use crate::{crypto, error::SmartWalletError, storage, types::SignaturePayload};

/// Custom account `__check_auth` implementation.
///
/// Soroban calls this function when another contract invokes `require_auth`
/// for an address that resolves to this smart wallet. It is the on-chain
/// equivalent of "verify the user's biometric signature before executing
/// the requested operation".
///
/// # Protocol
/// 1. Extract `credential_id`, `signature`, and the signed `SignaturePayload`
///    from `signature_payload` (the opaque bytes Soroban passes in).
/// 2. Look up the stored public key for that credential.
/// 3. Reconstruct the payload hash (`SHA-256(nonce_le || operation_hash)`).
/// 4. Call the native `secp256r1_verify` host function.
/// 5. Validate the nonce and advance it atomically.
///
/// # Arguments (passed by the Soroban host)
/// * `signature_payload` – the raw bytes the relayer attached; decoded to
///   [`AuthPayload`] inside this function.
/// * `auth_context`      – the list of Soroban auth-context entries that the
///   host is authorising (unused — we verify the operation hash directly).
///
/// The function returns `Ok(())` on success or a [`SmartWalletError`] on any
/// failure, which causes the host to revert the entire transaction.
pub fn check_auth(
    env: &Env,
    signature_payload: &AuthPayload,
    _auth_context: &Vec<Context>,
) -> Result<(), SmartWalletError> {
    // ── 1. Look up the registered credential ─────────────────────────────────
    let credential = storage::load_credential(env, &signature_payload.credential_id)
        .ok_or(SmartWalletError::CredentialNotFound)?;

    // ── 2. Validate nonce ─────────────────────────────────────────────────────
    let current_nonce = storage::get_nonce(env);
    if signature_payload.signed.nonce != current_nonce {
        return Err(SmartWalletError::InvalidNonce);
    }

    // ── 3. Reconstruct and verify payload hash ────────────────────────────────
    let payload_hash = crypto::hash_payload(
        env,
        signature_payload.signed.nonce,
        &signature_payload.signed.operation_hash,
    );

    crypto::verify_secp256r1(
        env,
        &credential.public_key,
        &payload_hash,
        &signature_payload.signature,
    )?;

    // ── 4. Advance nonce (replay protection) ──────────────────────────────────
    storage::set_nonce(env, current_nonce + 1);

    // ── 5. Bump TTLs so the wallet stays alive ────────────────────────────────
    storage::bump_credential_ttl(env, &signature_payload.credential_id);
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
