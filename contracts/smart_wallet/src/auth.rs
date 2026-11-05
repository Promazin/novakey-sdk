use soroban_sdk::{auth::Context, crypto::Hash, Bytes, BytesN, Env, Vec};

use crate::{
    crypto, error::SmartWalletError, events, nonce, storage,
    types::SignaturePayload,
};

/// Encode 32 bytes into standard URL-safe unpadded Base64 (RFC 4648 §5, 43 chars).
fn base64url_encode_32(input: &[u8; 32]) -> [u8; 43] {
    const URL_SAFE_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = [0u8; 43];
    let mut in_idx = 0;
    let mut out_idx = 0;

    for _ in 0..10 {
        let b0 = input[in_idx] as usize;
        let b1 = input[in_idx + 1] as usize;
        let b2 = input[in_idx + 2] as usize;
        out[out_idx] = URL_SAFE_ALPHABET[(b0 >> 2) & 0x3f];
        out[out_idx + 1] = URL_SAFE_ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3f];
        out[out_idx + 2] = URL_SAFE_ALPHABET[((b1 << 2) | (b2 >> 6)) & 0x3f];
        out[out_idx + 3] = URL_SAFE_ALPHABET[b2 & 0x3f];
        in_idx += 3;
        out_idx += 4;
    }

    let b0 = input[30] as usize;
    let b1 = input[31] as usize;
    out[40] = URL_SAFE_ALPHABET[(b0 >> 2) & 0x3f];
    out[41] = URL_SAFE_ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3f];
    out[42] = URL_SAFE_ALPHABET[(b1 << 2) & 0x3f];

    out
}

/// Search for a subslice inside a Soroban `Bytes` buffer.
fn bytes_contains_subslice(haystack: &Bytes, needle: &[u8]) -> bool {
    let h_len = haystack.len() as usize;
    let n_len = needle.len();
    if n_len == 0 {
        return true;
    }
    if h_len < n_len {
        return false;
    }
    for i in 0..=(h_len - n_len) {
        let mut matched = true;
        for j in 0..n_len {
            if haystack.get((i + j) as u32) != Some(needle[j]) {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

/// Verify a WebAuthn biometric assertion against the registered credential key.
fn verify_webauthn_signature(
    env: &Env,
    public_key: &BytesN<65>,
    payload_hash: &Hash<32>,
    operation_hash: &BytesN<32>,
    authenticator_data: &Bytes,
    client_data_json: &Bytes,
    signature: &BytesN<64>,
) -> Result<(), SmartWalletError> {
    if authenticator_data.len() < 37 {
        return Err(SmartWalletError::InvalidWebAuthnData);
    }

    // Verify user present flag (bit 0 must be 1)
    let flags = authenticator_data.get(32).unwrap_or(0);
    if (flags & 0x01) == 0 {
        return Err(SmartWalletError::InvalidWebAuthnData);
    }

    // Challenge can be base64url of operation_hash or payload_hash
    let challenge_op = base64url_encode_32(&operation_hash.to_array());
    let challenge_payload = base64url_encode_32(&payload_hash.to_bytes().to_array());

    if !bytes_contains_subslice(client_data_json, &challenge_op)
        && !bytes_contains_subslice(client_data_json, &challenge_payload)
    {
        return Err(SmartWalletError::InvalidWebAuthnData);
    }

    // WebAuthn authenticator signs SHA-256(authenticatorData || SHA-256(clientDataJSON))
    let client_data_hash = env.crypto().sha256(client_data_json);
    let mut signed_data = Bytes::new(env);
    signed_data.append(authenticator_data);
    let c_hash_bytes: Bytes = client_data_hash.to_bytes().into();
    signed_data.append(&c_hash_bytes);
    let final_digest = env.crypto().sha256(&signed_data);

    crypto::verify_secp256r1(env, public_key, &final_digest, signature)?;

    Ok(())
}

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
/// 4. Verify secp256r1 signature (via WebAuthn envelope if supplied, or direct digest).
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
    // ── Emergency Lock Check ──────────────────────────────────────────────────
    if storage::is_locked(env) {
        return Err(SmartWalletError::WalletLocked);
    }

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
    if !auth_payload.authenticator_data.is_empty() {
        verify_webauthn_signature(
            env,
            &credential.public_key,
            &payload_hash,
            &auth_payload.signed.operation_hash,
            &auth_payload.authenticator_data,
            &auth_payload.client_data_json,
            &auth_payload.signature,
        )?;
    } else {
        crypto::verify_secp256r1(
            env,
            &credential.public_key,
            &payload_hash,
            &auth_payload.signature,
        )?;
    }

    // ── 5. Bump TTLs so the wallet stays alive ────────────────────────────────
    storage::bump_credential_ttl(env, &auth_payload.credential_id);
    storage::bump_instance_ttl(env);

    // ── 6. Emit auth success event ────────────────────────────────────────────
    events::auth_success(
        env,
        &auth_payload.credential_id,
        auth_payload.signed.nonce,
        &auth_payload.signed.operation_hash,
    );

    Ok(())
}

// ── AuthPayload type ──────────────────────────────────────────────────────────

use soroban_sdk::contracttype;

/// The structured bytes the TypeScript SDK encodes and attaches to every
/// sponsored transaction as the `signature_payload` argument.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthPayload {
    /// The 16-byte CBOR credential ID identifying which registered passkey
    /// produced this signature.
    pub credential_id: BytesN<16>,
    /// The payload the device enclave signed.
    pub signed: SignaturePayload,
    /// The secp256r1 signature (r || s, 32 bytes each, low-s normalised).
    pub signature: BytesN<64>,
    /// Raw WebAuthn authenticatorData (empty when using direct programmatic signing).
    pub authenticator_data: Bytes,
    /// Raw WebAuthn clientDataJSON (empty when using direct programmatic signing).
    pub client_data_json: Bytes,
}
