//! Unit and integration tests for Account Recovery flow.
//!
//! Covers guardian configuration, guardian removal, recovery execution,
//! credential replacement, nonce advancement, event emissions, and error handling.

#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Events as _},
    Address, Bytes, BytesN, Env,
};

use smart_wallet::{SmartWalletContract, SmartWalletContractClient, SmartWalletError};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn fake_pubkey(env: &Env, seed: u8) -> BytesN<65> {
    let mut raw = [0u8; 65];
    raw[0] = 0x04;
    raw[1] = seed;
    BytesN::from_array(env, &raw)
}

fn fake_cred_id(env: &Env, seed: u8) -> BytesN<16> {
    let mut raw = [0u8; 16];
    raw[0] = seed;
    BytesN::from_array(env, &raw)
}

fn setup<'a>(env: &'a Env) -> (SmartWalletContractClient<'a>, Address) {
    let contract_id = env.register_contract(None, SmartWalletContract);
    let client = SmartWalletContractClient::new(env, &contract_id);
    let owner = Address::generate(env);

    client.initialize(
        &owner,
        &fake_cred_id(env, 1),
        &fake_pubkey(env, 1),
        &Bytes::from_slice(env, b"Primary Phone"),
    );

    (client, owner)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_set_and_get_guardian() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env);

    assert_eq!(client.get_guardian(), None);

    let guardian = Address::generate(&env);
    client.set_guardian(&guardian);

    assert_eq!(client.get_guardian(), Some(guardian));
}

#[test]
fn test_remove_guardian() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env);

    let guardian = Address::generate(&env);
    client.set_guardian(&guardian);
    assert_eq!(client.get_guardian(), Some(guardian));

    client.remove_guardian();
    assert_eq!(client.get_guardian(), None);
}

#[test]
fn test_recover_wallet_without_guardian_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env);

    let new_cred = fake_cred_id(&env, 2);
    let new_pk = fake_pubkey(&env, 2);
    let label = Bytes::from_slice(&env, b"New Phone");

    let res = client.try_recover_wallet(&new_cred, &new_pk, &label);
    assert_eq!(res, Err(Ok(SmartWalletError::GuardianNotSet)));
}

#[test]
fn test_recover_wallet_replaces_credentials_and_advances_nonce() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env);

    let guardian = Address::generate(&env);
    client.set_guardian(&guardian);

    assert_eq!(client.get_nonce(), 0);
    assert_eq!(client.list_credentials().len(), 1);
    assert_eq!(client.list_credentials().get(0).unwrap(), fake_cred_id(&env, 1));

    // Execute recovery with new credential
    let new_cred = fake_cred_id(&env, 2);
    let new_pk = fake_pubkey(&env, 2);
    let label = Bytes::from_slice(&env, b"Recovered Device");

    client.recover_wallet(&new_cred, &new_pk, &label);

    // Old credential is no longer accessible
    let old_res = client.try_get_credential(&fake_cred_id(&env, 1));
    assert_eq!(old_res, Err(Ok(SmartWalletError::CredentialNotFound)));

    // New credential is the sole active credential
    let creds = client.list_credentials();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds.get(0).unwrap(), new_cred);

    let stored = client.get_credential(&new_cred);
    assert_eq!(stored.public_key, new_pk);

    // Nonce advanced to invalidate past signed payloads
    assert_eq!(client.get_nonce(), 1);

    // Verify recovery events were emitted
    let events = env.events().all();
    assert!(events.len() >= 3); // init, set_guardian, wallet_recovered
}

#[test]
fn test_recover_wallet_rejects_long_label() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env);

    let guardian = Address::generate(&env);
    client.set_guardian(&guardian);

    let new_cred = fake_cred_id(&env, 2);
    let new_pk = fake_pubkey(&env, 2);
    let long_label = Bytes::from_slice(&env, &[b'r'; 65]);

    let res = client.try_recover_wallet(&new_cred, &new_pk, &long_label);
    assert_eq!(res, Err(Ok(SmartWalletError::LabelTooLong)));
}

#[test]
fn test_recover_wallet_rejects_invalid_public_key() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = setup(&env);

    let guardian = Address::generate(&env);
    client.set_guardian(&guardian);

    let new_cred = fake_cred_id(&env, 2);
    let mut bad_pk = [0u8; 65];
    bad_pk[0] = 0x03; // compressed prefix, invalid for uncompressed 65-byte SEC1
    bad_pk[1] = 0x42;
    let label = Bytes::from_slice(&env, b"Recovered Phone");

    let res = client.try_recover_wallet(
        &new_cred,
        &BytesN::from_array(&env, &bad_pk),
        &label,
    );
    assert_eq!(res, Err(Ok(SmartWalletError::InvalidPublicKey)));
}

#[test]
fn test_recovery_uninitialized_returns_error() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SmartWalletContract);
    let client = SmartWalletContractClient::new(&env, &contract_id);

    let guardian = Address::generate(&env);
    assert_eq!(client.try_set_guardian(&guardian), Err(Ok(SmartWalletError::NotInitialized)));
    assert_eq!(client.try_get_guardian(), Err(Ok(SmartWalletError::NotInitialized)));
    assert_eq!(client.try_remove_guardian(), Err(Ok(SmartWalletError::NotInitialized)));

    let new_cred = fake_cred_id(&env, 2);
    let new_pk = fake_pubkey(&env, 2);
    let label = Bytes::from_slice(&env, b"device");
    assert_eq!(
        client.try_recover_wallet(&new_cred, &new_pk, &label),
        Err(Ok(SmartWalletError::NotInitialized))
    );
}
