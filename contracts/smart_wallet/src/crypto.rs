use soroban_sdk::{crypto::Hash, Bytes, BytesN, Env};

use crate::error::SmartWalletError;

// ── secp256r1 verification ────────────────────────────────────────────────────
//
// Stellar Protocol 21 exposes a native host function for verifying secp256r1
// (NIST P-256) signatures. This is the same curve used by WebAuthn / FIDO2
// device enclaves (FaceID, TouchID, Android Strongbox).
//
// Host function surface (soroban-sdk 21.x):
//   env.crypto().secp256r1_verify(public_key, message_digest, signature)
//
// Parameters
// ──────────
// public_key     : BytesN<65>  – uncompressed point: 0x04 || X(32) || Y(32)
// message_digest : Hash<32>    – SHA-256 hash of the signed payload
// signature      : BytesN<64>  – compact DER r(32) || s(32)

/// Verify a secp256r1 (P-256) signature produced by a WebAuthn authenticator.
///
/// # Arguments
/// * `public_key`   – 65-byte uncompressed secp256r1 public key.
/// * `payload_hash` – SHA-256 digest of the [`SignaturePayload`] XDR bytes.
/// * `signature`    – 64-byte compact signature (r || s), low-s normalised.
pub fn verify_secp256r1(
    env: &Env,
    public_key: &BytesN<65>,
    payload_hash: &Hash<32>,
    signature: &BytesN<64>,
) -> Result<(), SmartWalletError> {
    env.crypto()
        .secp256r1_verify(public_key, payload_hash, signature);

    Ok(())
}

/// Hash the raw serialised `SignaturePayload` bytes with SHA-256, producing
/// the 32-byte digest that was signed by the device enclave.
///
/// WebAuthn authenticators sign `SHA-256(authenticatorData || SHA-256(clientDataJSON))`.
/// For on-chain simplicity, NovaKey signs `SHA-256(nonce_le_bytes || operation_hash)`.
pub fn hash_payload(env: &Env, nonce: u64, operation_hash: &BytesN<32>) -> Hash<32> {
    let mut data = Bytes::new(env);

    // Append nonce as 8 little-endian bytes.
    let nonce_bytes = nonce.to_le_bytes();
    for b in nonce_bytes.iter() {
        data.push_back(*b);
    }

    // Append the 32-byte operation hash.
    data.append(&operation_hash.clone().into());

    env.crypto().sha256(&data)
}
