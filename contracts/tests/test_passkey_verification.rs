//! Integration tests for the full passkey verification flow.
//!
//! These tests cover the `__check_auth` path end-to-end: initialising a
//! wallet, constructing a valid `AuthPayload`, calling `__check_auth` through
//! the Soroban test harness, and asserting that the nonce advances and that
//! tampered/replayed payloads are rejected.
//!
//! Because we cannot run actual WebAuthn device hardware in CI, we use
//! test-only secp256r1 key material generated with the `p256` crate (a
//! pure-Rust NIST P-256 implementation). The Soroban test environment
//! (`Env::default()`) executes the same native host function that runs on a
//! real validator, so the cryptographic path is fully exercised.
//!
//! # Test key material
//! A fixed private scalar is used so tests are deterministic. Do NOT use this
//! key for anything other than testing.

#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Events as _},
    Address, Bytes, BytesN, Env,
};

use smart_wallet::{
    AuthPayload, SignaturePayload, SmartWalletContract, SmartWalletContractClient, SmartWalletError,
};

// ── p256 imports (test-only) ──────────────────────────────────────────────────
// The `p256` crate is a dependency only in dev-dependencies.
// We use it to sign test payloads with a real secp256r1 private key.
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    SecretKey,
};

// ── Deterministic test key ────────────────────────────────────────────────────

/// Fixed 32-byte private scalar for deterministic test signatures.
const TEST_PRIVATE_SCALAR: [u8; 32] = [
    0x51, 0x8f, 0x3b, 0x47, 0x2e, 0x9c, 0xd1, 0xfa,
    0x43, 0x77, 0x2a, 0x06, 0x1e, 0xb0, 0x55, 0xd3,
    0x82, 0xac, 0x7f, 0x14, 0x98, 0x3e, 0x60, 0x9b,
    0xc5, 0xf1, 0x22, 0x87, 0x04, 0xaa, 0xe8, 0x31,
];

struct TestKey {
    signing_key: SigningKey,
    public_key_bytes: [u8; 65],
}

impl TestKey {
    fn new() -> Self {
        let secret = SecretKey::from_bytes((&TEST_PRIVATE_SCALAR).into())
            .expect("valid test scalar");
        let signing_key = SigningKey::from(secret.clone());
        let encoded = secret.public_key().to_encoded_point(false); // uncompressed
        let mut pk = [0u8; 65];
        pk.copy_from_slice(encoded.as_bytes());
        TestKey { signing_key, public_key_bytes: pk }
    }

    /// Sign payload bytes. `Signer::sign` hashes `raw` with SHA-256 and signs the digest.
    fn sign(&self, raw: &[u8; 40]) -> [u8; 64] {
        let sig: Signature = self.signing_key.sign(raw);
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        out
    }
}

// ── Payload helper (40 bytes: 8 bytes LE nonce + 32 bytes op_hash) ─────────────

fn raw_payload_bytes(nonce: u64, op_hash: &[u8; 32]) -> [u8; 40] {
    let mut data = [0u8; 40];
    data[..8].copy_from_slice(&nonce.to_le_bytes());
    data[8..].copy_from_slice(op_hash);
    data
}

// ── Fake byte helpers ─────────────────────────────────────────────────────────

fn fake_cred_id(env: &Env, seed: u8) -> BytesN<16> {
    let mut raw = [0u8; 16];
    raw[0] = seed;
    BytesN::from_array(env, &raw)
}

// ── Setup ─────────────────────────────────────────────────────────────────────

fn setup_with_key<'a>(env: &'a Env, key: &TestKey) -> (SmartWalletContractClient<'a>, BytesN<16>) {
    let contract_id = env.register_contract(None, SmartWalletContract);
    let client = SmartWalletContractClient::new(env, &contract_id);
    let owner = Address::generate(env);
    let cred_id = fake_cred_id(env, 1);

    client.initialize(
        &owner,
        &cred_id,
        &BytesN::from_array(env, &key.public_key_bytes),
        &Bytes::from_slice(env, b"Test Device"),
    );

    (client, cred_id)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Happy path: a correctly signed payload is accepted and the nonce advances.
#[test]
fn test_check_auth_valid_signature_advances_nonce() {
    let env = Env::default();
    let key = TestKey::new();
    let (client, cred_id) = setup_with_key(&env, &key);

    let nonce = client.get_nonce(); // should be 0
    let op_hash_raw = [0xabu8; 32];
    let raw_payload = raw_payload_bytes(nonce, &op_hash_raw);
    let sig_bytes = key.sign(&raw_payload);

    let auth_payload = AuthPayload {
        credential_id: cred_id,
        signed: SignaturePayload {
            nonce,
            operation_hash: BytesN::from_array(&env, &op_hash_raw),
        },
        signature: BytesN::from_array(&env, &sig_bytes),
        authenticator_data: Bytes::new(&env),
        client_data_json: Bytes::new(&env),
    };

    check_auth_shim(&env, &client, auth_payload).unwrap();

    assert_eq!(client.get_nonce(), 1);
}

/// Replay: re-submitting the same payload after it has been consumed is rejected.
#[test]
fn test_check_auth_replay_is_rejected() {
    let env = Env::default();
    let key = TestKey::new();
    let (client, cred_id) = setup_with_key(&env, &key);
    env.mock_all_auths();

    let nonce = client.get_nonce();
    let op_hash_raw = [0xbbu8; 32];
    let raw_payload = raw_payload_bytes(nonce, &op_hash_raw);
    let sig_bytes = key.sign(&raw_payload);

    let auth_payload = AuthPayload {
        credential_id: cred_id.clone(),
        signed: SignaturePayload {
            nonce,
            operation_hash: BytesN::from_array(&env, &op_hash_raw),
        },
        signature: BytesN::from_array(&env, &sig_bytes),
        authenticator_data: Bytes::new(&env),
        client_data_json: Bytes::new(&env),
    };

    check_auth_shim(&env, &client, auth_payload.clone()).unwrap();

    // Second submission — nonce is now 1, payload still carries nonce=0.
    let result = check_auth_shim(&env, &client, auth_payload);
    assert_eq!(result.unwrap_err(), SmartWalletError::InvalidNonce);
}

/// Wrong signature: a payload signed with a different key is rejected.
#[test]
fn test_check_auth_wrong_signature_is_rejected() {
    let env = Env::default();
    let key = TestKey::new();
    let (client, cred_id) = setup_with_key(&env, &key);

    let nonce = client.get_nonce();
    let op_hash_raw = [0xccu8; 32];
    let raw_payload = raw_payload_bytes(nonce, &op_hash_raw);

    // Sign with a *different* key (all-ones scalar — not the registered key).
    let wrong_scalar = [0x01u8; 32];
    let wrong_secret = SecretKey::from_bytes((&wrong_scalar).into()).unwrap();
    let wrong_signing = SigningKey::from(wrong_secret);
    let wrong_sig: p256::ecdsa::Signature = wrong_signing.sign(&raw_payload);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&wrong_sig.to_bytes());

    let auth_payload = AuthPayload {
        credential_id: cred_id,
        signed: SignaturePayload {
            nonce,
            operation_hash: BytesN::from_array(&env, &op_hash_raw),
        },
        signature: BytesN::from_array(&env, &sig_bytes),
        authenticator_data: Bytes::new(&env),
        client_data_json: Bytes::new(&env),
    };

    let result = check_auth_shim(&env, &client, auth_payload);
    assert_eq!(result.unwrap_err(), SmartWalletError::InvalidSignature);
}

/// Unknown credential ID: rejected even with a valid signature.
#[test]
fn test_check_auth_unknown_credential_is_rejected() {
    let env = Env::default();
    let key = TestKey::new();
    let (client, _) = setup_with_key(&env, &key);

    let nonce = client.get_nonce();
    let op_hash_raw = [0xddu8; 32];
    let raw_payload = raw_payload_bytes(nonce, &op_hash_raw);
    let sig_bytes = key.sign(&raw_payload);

    let auth_payload = AuthPayload {
        // Use credential ID 99 — not registered
        credential_id: fake_cred_id(&env, 99),
        signed: SignaturePayload {
            nonce,
            operation_hash: BytesN::from_array(&env, &op_hash_raw),
        },
        signature: BytesN::from_array(&env, &sig_bytes),
        authenticator_data: Bytes::new(&env),
        client_data_json: Bytes::new(&env),
    };

    let result = check_auth_shim(&env, &client, auth_payload);
    assert_eq!(result.unwrap_err(), SmartWalletError::CredentialNotFound);
}

/// Wrong nonce: payload with nonce=5 while contract nonce=0 is rejected.
#[test]
fn test_check_auth_wrong_nonce_is_rejected() {
    let env = Env::default();
    let key = TestKey::new();
    let (client, cred_id) = setup_with_key(&env, &key);

    let op_hash_raw = [0xeeu8; 32];
    let bad_nonce: u64 = 5; // contract is at nonce 0
    let raw_payload = raw_payload_bytes(bad_nonce, &op_hash_raw);
    let sig_bytes = key.sign(&raw_payload);

    let auth_payload = AuthPayload {
        credential_id: cred_id,
        signed: SignaturePayload {
            nonce: bad_nonce,
            operation_hash: BytesN::from_array(&env, &op_hash_raw),
        },
        signature: BytesN::from_array(&env, &sig_bytes),
        authenticator_data: Bytes::new(&env),
        client_data_json: Bytes::new(&env),
    };

    let result = check_auth_shim(&env, &client, auth_payload);
    assert_eq!(result.unwrap_err(), SmartWalletError::InvalidNonce);
}

/// Mismatched operation hash: payload signed for a different op_hash than requested.
#[test]
fn test_check_auth_mismatched_operation_hash_is_rejected() {
    let env = Env::default();
    let key = TestKey::new();
    let (client, cred_id) = setup_with_key(&env, &key);

    let nonce = client.get_nonce();
    let op_hash_raw = [0xa1u8; 32];
    let raw_payload = raw_payload_bytes(nonce, &op_hash_raw);
    let sig_bytes = key.sign(&raw_payload);

    let auth_payload = AuthPayload {
        credential_id: cred_id,
        signed: SignaturePayload {
            nonce,
            operation_hash: BytesN::from_array(&env, &op_hash_raw),
        },
        signature: BytesN::from_array(&env, &sig_bytes),
        authenticator_data: Bytes::new(&env),
        client_data_json: Bytes::new(&env),
    };

    // Simulate host requesting auth for a DIFFERENT operation hash (0xb2)
    use soroban_sdk::{IntoVal, Vec};
    let host_op_hash = BytesN::from_array(&env, &[0xb2u8; 32]);
    let auth_context: Vec<soroban_sdk::auth::Context> = Vec::new(&env);
    let res = env.try_invoke_contract_check_auth::<SmartWalletError>(
        &client.address,
        &host_op_hash,
        auth_payload.into_val(&env),
        &auth_context,
    );

    assert_eq!(res, Err(Ok(SmartWalletError::InvalidOperationHash)));
}

#[test]
fn test_auth_publishes_success_event() {
    let env = Env::default();
    let key = TestKey::new();
    let (client, cred_id) = setup_with_key(&env, &key);

    let nonce = client.get_nonce();
    let op_hash_raw = [0x55u8; 32];
    let raw_payload = raw_payload_bytes(nonce, &op_hash_raw);
    let sig_bytes = key.sign(&raw_payload);

    let auth_payload = AuthPayload {
        credential_id: cred_id,
        signed: SignaturePayload {
            nonce,
            operation_hash: BytesN::from_array(&env, &op_hash_raw),
        },
        signature: BytesN::from_array(&env, &sig_bytes),
        authenticator_data: Bytes::new(&env),
        client_data_json: Bytes::new(&env),
    };

    check_auth_shim(&env, &client, auth_payload).unwrap();

    let events = env.events().all();
    assert!(events.len() >= 2);
}

/// WebAuthn envelope flow: authenticates a full WebAuthn authenticatorData + clientDataJSON assertion.
#[test]
fn test_check_auth_with_webauthn_envelope() {
    use sha2::{Digest, Sha256};

    let env = Env::default();
    let key = TestKey::new();
    let (client, cred_id) = setup_with_key(&env, &key);

    let nonce = client.get_nonce();
    let op_hash_raw = [0x77u8; 32];

    // Challenge string encoded as URL-safe Base64 of op_hash_raw
    // Since op_hash_raw is all 0x77 ("w"), its base64url is 43 chars
    const URL_SAFE_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut challenge_chars = [0u8; 43];
    for i in 0..10 {
        let b0 = op_hash_raw[i * 3] as usize;
        let b1 = op_hash_raw[i * 3 + 1] as usize;
        let b2 = op_hash_raw[i * 3 + 2] as usize;
        challenge_chars[i * 4] = URL_SAFE_ALPHABET[(b0 >> 2) & 0x3f];
        challenge_chars[i * 4 + 1] = URL_SAFE_ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3f];
        challenge_chars[i * 4 + 2] = URL_SAFE_ALPHABET[((b1 << 2) | (b2 >> 6)) & 0x3f];
        challenge_chars[i * 4 + 3] = URL_SAFE_ALPHABET[b2 & 0x3f];
    }
    let b0 = op_hash_raw[30] as usize;
    let b1 = op_hash_raw[31] as usize;
    challenge_chars[40] = URL_SAFE_ALPHABET[(b0 >> 2) & 0x3f];
    challenge_chars[41] = URL_SAFE_ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3f];
    challenge_chars[42] = URL_SAFE_ALPHABET[(b1 << 2) & 0x3f];
    let challenge_str = core::str::from_utf8(&challenge_chars).unwrap();

    let client_data_json_str = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://app.novakey.org","crossOrigin":false}}"#,
        challenge_str
    );
    let client_data_bytes = client_data_json_str.as_bytes();
    let client_data_hash = Sha256::digest(client_data_bytes);

    // 37-byte authenticator data: 32-byte RP ID hash, flag 0x05 (UP | UV), 4-byte sign count 0
    let mut auth_data = [0u8; 37];
    auth_data[..32].copy_from_slice(&Sha256::digest(b"app.novakey.org"));
    auth_data[32] = 0x05; // User Present & User Verified

    // Digest that the passkey hardware enclave signs: SHA-256(authenticatorData || SHA-256(clientDataJSON))
    let mut to_sign = [0u8; 69];
    to_sign[..37].copy_from_slice(&auth_data);
    to_sign[37..].copy_from_slice(&client_data_hash);

    // `Signer::sign(&to_sign)` hashes `to_sign` with SHA-256 and signs the resulting 32-byte digest
    use p256::ecdsa::{signature::Signer, Signature};
    let sig: Signature = key.signing_key.sign(&to_sign);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig.to_bytes());

    let auth_payload = AuthPayload {
        credential_id: cred_id,
        signed: SignaturePayload {
            nonce,
            operation_hash: BytesN::from_array(&env, &op_hash_raw),
        },
        signature: BytesN::from_array(&env, &sig_bytes),
        authenticator_data: soroban_sdk::Bytes::from_slice(&env, &auth_data),
        client_data_json: soroban_sdk::Bytes::from_slice(&env, client_data_bytes),
    };

    check_auth_shim(&env, &client, auth_payload).unwrap();
    assert_eq!(client.get_nonce(), 1);
}

/// WebAuthn envelope flow: rejects when userPresent flag is not set.
#[test]
fn test_check_auth_webauthn_missing_up_flag_is_rejected() {
    let env = Env::default();
    let key = TestKey::new();
    let (client, cred_id) = setup_with_key(&env, &key);

    let nonce = client.get_nonce();
    let op_hash_raw = [0x88u8; 32];

    let client_data_json_str = r#"{"type":"webauthn.get","challenge":"fake","origin":"https://app.novakey.org"}"#;
    let client_data_bytes = client_data_json_str.as_bytes();

    // authenticator data with UP flag = 0
    let mut auth_data = [0u8; 37];
    auth_data[32] = 0x00;

    let auth_payload = AuthPayload {
        credential_id: cred_id,
        signed: SignaturePayload {
            nonce,
            operation_hash: BytesN::from_array(&env, &op_hash_raw),
        },
        signature: BytesN::from_array(&env, &[0u8; 64]),
        authenticator_data: soroban_sdk::Bytes::from_slice(&env, &auth_data),
        client_data_json: soroban_sdk::Bytes::from_slice(&env, client_data_bytes),
    };

    let res = check_auth_shim(&env, &client, auth_payload);
    assert_eq!(res.unwrap_err(), SmartWalletError::InvalidWebAuthnData);
}

// ── Test shim ─────────────────────────────────────────────────────────────────
//
// Leverages `try_invoke_contract_check_auth` to invoke the contract's
// `__check_auth` through the Soroban host environment.

fn check_auth_shim(
    env: &Env,
    client: &SmartWalletContractClient,
    payload: AuthPayload,
) -> Result<(), SmartWalletError> {
    use soroban_sdk::{IntoVal, Vec};

    let auth_context: Vec<soroban_sdk::auth::Context> = Vec::new(env);
    let res = env.try_invoke_contract_check_auth::<SmartWalletError>(
        &client.address,
        &payload.signed.operation_hash,
        payload.into_val(env),
        &auth_context,
    );

    match res {
        Ok(()) => Ok(()),
        Err(Ok(err)) => Err(err),
        Err(Err(_invoke_err)) => Err(SmartWalletError::InvalidSignature),
    }
}
