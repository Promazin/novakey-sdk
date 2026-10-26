//! Unit tests for credential registration logic.
//!
//! These tests exercise `SmartWalletContract::initialize`, `add_credential`,
//! `remove_credential`, `list_credentials`, and the error paths defined in
//! `SmartWalletError`. They run entirely in the Soroban test environment
//! (no real Stellar node required).

#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Events as _},
    Address, Bytes, BytesN, Env,
};

use smart_wallet::{SmartWalletContract, SmartWalletContractClient, SmartWalletError};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a fake 65-byte uncompressed secp256r1 public key for testing.
/// Real keys must be on the P-256 curve; for unit tests we just need bytes.
fn fake_pubkey(env: &Env, seed: u8) -> BytesN<65> {
    let mut raw = [0u8; 65];
    raw[0] = 0x04; // uncompressed point prefix
    raw[1] = seed;
    BytesN::from_array(env, &raw)
}

/// Build a fake 16-byte credential ID.
fn fake_cred_id(env: &Env, seed: u8) -> BytesN<16> {
    let mut raw = [0u8; 16];
    raw[0] = seed;
    BytesN::from_array(env, &raw)
}

/// Deploy a fresh SmartWallet and return (client, owner_address).
fn setup<'a>(env: &'a Env) -> (SmartWalletContractClient<'a>, Address) {
    let contract_id = env.register_contract(None, SmartWalletContract);
    let client = SmartWalletContractClient::new(env, &contract_id);
    let owner = Address::generate(env);

    client.initialize(
        &owner,
        &fake_cred_id(env, 1),
        &fake_pubkey(env, 1),
        &Bytes::from_slice(env, b"iPhone 15 FaceID"),
    );

    (client, owner)
}

// ── initialize ────────────────────────────────────────────────────────────────

#[test]
fn test_initialize_sets_owner() {
    let env = Env::default();
    let (client, owner) = setup(&env);
    assert_eq!(client.owner(), owner);
}

#[test]
fn test_initialize_sets_nonce_to_zero() {
    let env = Env::default();
    let (client, _) = setup(&env);
    assert_eq!(client.get_nonce(), 0);
}

#[test]
fn test_initialize_registers_first_credential() {
    let env = Env::default();
    let (client, _) = setup(&env);
    let ids = client.list_credentials();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids.get(0).unwrap(), fake_cred_id(&env, 1));
}

#[test]
fn test_initialize_returns_error_if_called_twice() {
    let env = Env::default();
    let (client, owner) = setup(&env);

    let result = client.try_initialize(
        &owner,
        &fake_cred_id(&env, 2),
        &fake_pubkey(&env, 2),
        &Bytes::from_slice(&env, b"second call"),
    );

    assert_eq!(result, Err(Ok(SmartWalletError::AlreadyInitialized)));
}

#[test]
fn test_initialize_rejects_label_too_long() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SmartWalletContract);
    let client = SmartWalletContractClient::new(&env, &contract_id);
    let owner = Address::generate(&env);

    // 65-byte label — one byte over the 64-byte limit
    let long_label = Bytes::from_slice(&env, &[b'x'; 65]);

    let result = client.try_initialize(
        &owner,
        &fake_cred_id(&env, 1),
        &fake_pubkey(&env, 1),
        &long_label,
    );

    assert_eq!(result, Err(Ok(SmartWalletError::LabelTooLong)));
}

// ── add_credential ────────────────────────────────────────────────────────────

#[test]
fn test_add_credential_increases_count() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env);

    client.add_credential(
        &fake_cred_id(&env, 2),
        &fake_pubkey(&env, 2),
        &Bytes::from_slice(&env, b"Pixel 8 Fingerprint"),
    );

    assert_eq!(client.list_credentials().len(), 2);
}

#[test]
fn test_add_credential_rejects_duplicate_id() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env);

    // credential ID 1 was registered in setup()
    let result = client.try_add_credential(
        &fake_cred_id(&env, 1),
        &fake_pubkey(&env, 99),
        &Bytes::from_slice(&env, b"duplicate"),
    );

    assert_eq!(result, Err(Ok(SmartWalletError::CredentialAlreadyExists)));
}

#[test]
fn test_add_credential_rejects_label_too_long() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env);

    let result = client.try_add_credential(
        &fake_cred_id(&env, 3),
        &fake_pubkey(&env, 3),
        &Bytes::from_slice(&env, &[b'a'; 65]),
    );

    assert_eq!(result, Err(Ok(SmartWalletError::LabelTooLong)));
}

#[test]
fn test_add_credential_enforces_max_limit() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env); // 1 credential already registered

    // Add credentials 2–10 (9 more, total 10)
    for seed in 2u8..=10 {
        client.add_credential(
            &fake_cred_id(&env, seed),
            &fake_pubkey(&env, seed),
            &Bytes::from_slice(&env, b"device"),
        );
    }

    assert_eq!(client.list_credentials().len(), 10);

    // The 11th should fail
    let result = client.try_add_credential(
        &fake_cred_id(&env, 11),
        &fake_pubkey(&env, 11),
        &Bytes::from_slice(&env, b"overflow"),
    );

    assert_eq!(result, Err(Ok(SmartWalletError::MaxCredentialsReached)));
}

// ── remove_credential ─────────────────────────────────────────────────────────

#[test]
fn test_remove_credential_decreases_count() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env);

    // Add a second credential so we can remove one without hitting the lock guard.
    client.add_credential(
        &fake_cred_id(&env, 2),
        &fake_pubkey(&env, 2),
        &Bytes::from_slice(&env, b"second device"),
    );

    client.remove_credential(&fake_cred_id(&env, 2));

    assert_eq!(client.list_credentials().len(), 1);
}

#[test]
fn test_remove_last_credential_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env); // only 1 credential

    let result = client.try_remove_credential(&fake_cred_id(&env, 1));
    assert_eq!(result, Err(Ok(SmartWalletError::CannotRemoveLastCredential)));
}

#[test]
fn test_remove_nonexistent_credential_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env);

    let result = client.try_remove_credential(&fake_cred_id(&env, 99));
    assert_eq!(result, Err(Ok(SmartWalletError::CredentialNotFound)));
}

// ── get_credential ────────────────────────────────────────────────────────────

#[test]
fn test_get_credential_returns_correct_pubkey() {
    let env = Env::default();
    let (client, _) = setup(&env);

    let cred = client.get_credential(&fake_cred_id(&env, 1));
    assert_eq!(cred.public_key, fake_pubkey(&env, 1));
}

#[test]
fn test_get_credential_returns_error_for_unknown_id() {
    let env = Env::default();
    let (client, _) = setup(&env);

    let result = client.try_get_credential(&fake_cred_id(&env, 42));
    assert_eq!(result, Err(Ok(SmartWalletError::CredentialNotFound)));
}

// ── uninitialized guard ───────────────────────────────────────────────────────

#[test]
fn test_get_nonce_on_uninitialised_wallet_returns_error() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SmartWalletContract);
    let client = SmartWalletContractClient::new(&env, &contract_id);

    let result = client.try_get_nonce();
    assert_eq!(result, Err(Ok(SmartWalletError::NotInitialized)));
}

// ── Events ────────────────────────────────────────────────────────────────────

#[test]
fn test_registration_publishes_event() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SmartWalletContract);
    let client = SmartWalletContractClient::new(&env, &contract_id);
    let owner = Address::generate(&env);

    client.initialize(
        &owner,
        &fake_cred_id(&env, 1),
        &fake_pubkey(&env, 1),
        &Bytes::from_slice(&env, b"Phone"),
    );

    let events = env.events().all();
    assert!(!events.is_empty());
}

#[test]
fn test_deregistration_publishes_event() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env);

    client.add_credential(
        &fake_cred_id(&env, 2),
        &fake_pubkey(&env, 2),
        &Bytes::from_slice(&env, b"second"),
    );

    let count_before = env.events().all().len();
    client.remove_credential(&fake_cred_id(&env, 2));
    let count_after = env.events().all().len();

    assert_eq!(count_after, count_before + 1);
}
