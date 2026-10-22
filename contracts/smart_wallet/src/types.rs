use soroban_sdk::{contracttype, Bytes, BytesN};

/// A registered passkey credential bound to this smart wallet.
///
/// The `public_key` is a 65-byte uncompressed secp256r1 public key
/// (`04 || x || y`) exported from the device's Secure Enclave during
/// WebAuthn registration.
#[contracttype]
#[derive(Clone, Debug)]
pub struct Credential {
    /// Uncompressed secp256r1 public key (65 bytes: 0x04 || X || Y).
    pub public_key: BytesN<65>,
    /// Human-readable label for UX (e.g. "iPhone 14 FaceID").
    pub label: Bytes,
}

/// The payload that the client signs with the passkey private key.
///
/// This mirrors the WebAuthn `clientDataJSON` + `authenticatorData` structure
/// but reduced to what the on-chain verifier needs.
#[contracttype]
#[derive(Clone, Debug)]
pub struct SignaturePayload {
    /// Nonce prevents replay attacks. Must equal the contract's current nonce.
    pub nonce: u64,
    /// The Soroban operation being authorised (encoded as raw XDR bytes).
    pub operation_hash: BytesN<32>,
}
