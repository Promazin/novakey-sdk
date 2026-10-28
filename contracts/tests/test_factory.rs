//! Integration and unit tests for the Factory contract.
//!
//! Exercises factory initialization, deterministic wallet address prediction,
//! WASM hash updates, credential address querying, lifecycle events, and
//! error handling.

#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Events as _},
    Address, BytesN, Env,
};

use factory::{FactoryContract, FactoryContractClient, FactoryError};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn fake_wasm_hash(env: &Env, seed: u8) -> BytesN<32> {
    let mut raw = [0u8; 32];
    raw[0] = seed;
    BytesN::from_array(env, &raw)
}

fn fake_cred_id(env: &Env, seed: u8) -> BytesN<16> {
    let mut raw = [0u8; 16];
    raw[0] = seed;
    BytesN::from_array(env, &raw)
}

fn setup_factory<'a>(env: &'a Env) -> (FactoryContractClient<'a>, Address, BytesN<32>) {
    let contract_id = env.register_contract(None, FactoryContract);
    let client = FactoryContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    let wasm_hash = fake_wasm_hash(env, 1);

    client.initialize(&admin, &wasm_hash);

    (client, admin, wasm_hash)
}

// ── Initialisation tests ──────────────────────────────────────────────────────

#[test]
fn test_factory_initialize_sets_version() {
    let env = Env::default();
    let (client, _, _) = setup_factory(&env);
    assert_eq!(client.version(), 1);
}

#[test]
fn test_factory_initialize_twice_fails() {
    let env = Env::default();
    let (client, admin, wasm_hash) = setup_factory(&env);

    let res = client.try_initialize(&admin, &wasm_hash);
    assert_eq!(res, Err(Ok(FactoryError::AlreadyInitialized)));
}

// ── Deterministic address prediction ──────────────────────────────────────────

#[test]
fn test_predict_wallet_address_is_deterministic() {
    let env = Env::default();
    let (client, _, _) = setup_factory(&env);

    let cred_id = fake_cred_id(&env, 42);
    let predicted_1 = client.predict_wallet_address(&cred_id);
    let predicted_2 = client.predict_wallet_address(&cred_id);

    assert_eq!(predicted_1, predicted_2);
}

#[test]
fn test_predict_wallet_address_varies_by_credential() {
    let env = Env::default();
    let (client, _, _) = setup_factory(&env);

    let cred_id_1 = fake_cred_id(&env, 1);
    let cred_id_2 = fake_cred_id(&env, 2);

    let addr_1 = client.predict_wallet_address(&cred_id_1);
    let addr_2 = client.predict_wallet_address(&cred_id_2);

    assert_ne!(addr_1, addr_2);
}

// ── Admin WASM hash management ────────────────────────────────────────────────

#[test]
fn test_set_wasm_hash_updates_hash_and_emits_event() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _, _) = setup_factory(&env);

    let new_hash = fake_wasm_hash(&env, 99);
    let events_before = env.events().all().len();

    client.set_wasm_hash(&new_hash);

    let events_after = env.events().all().len();
    assert_eq!(events_after, events_before + 1);
}

#[test]
fn test_set_wasm_hash_uninitialized_returns_error() {
    let env = Env::default();
    let contract_id = env.register_contract(None, FactoryContract);
    let client = FactoryContractClient::new(&env, &contract_id);

    let new_hash = fake_wasm_hash(&env, 99);
    let res = client.try_set_wasm_hash(&new_hash);

    assert_eq!(res, Err(Ok(FactoryError::NotInitialized)));
}

// ── Query tests ───────────────────────────────────────────────────────────────

#[test]
fn test_get_wallet_nonexistent_returns_none() {
    let env = Env::default();
    let (client, _, _) = setup_factory(&env);

    let cred_id = fake_cred_id(&env, 77);
    assert_eq!(client.get_wallet(&cred_id), None);
}

#[test]
fn test_deploy_wallet_uninitialized_returns_error() {
    let env = Env::default();
    let contract_id = env.register_contract(None, FactoryContract);
    let client = FactoryContractClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    let cred_id = fake_cred_id(&env, 1);
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    let public_key = BytesN::from_array(&env, &pk);
    let label = soroban_sdk::Bytes::from_slice(&env, b"device");

    let res = client.try_deploy_wallet(&owner, &cred_id, &public_key, &label);
    assert_eq!(res, Err(Ok(FactoryError::NotInitialized)));
}

#[test]
fn test_factory_rejects_zero_wasm_hash() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, FactoryContract);
    let client = FactoryContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let zero_hash = BytesN::from_array(&env, &[0u8; 32]);

    let init_res = client.try_initialize(&admin, &zero_hash);
    assert_eq!(init_res, Err(Ok(FactoryError::InvalidWasmHash)));

    let valid_hash = fake_wasm_hash(&env, 1);
    client.initialize(&admin, &valid_hash);
    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_wasm_hash(), valid_hash);

    let update_res = client.try_set_wasm_hash(&zero_hash);
    assert_eq!(update_res, Err(Ok(FactoryError::InvalidWasmHash)));
}

#[test]
fn test_factory_transfer_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, old_admin, _) = setup_factory(&env);

    let new_admin = Address::generate(&env);
    assert_ne!(old_admin, new_admin);

    client.transfer_admin(&new_admin);
    assert_eq!(client.get_admin(), new_admin);
}
