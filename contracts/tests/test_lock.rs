//! Integration and unit tests for the emergency wallet lock and security freeze mechanism.

#![cfg(test)]

use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    SecretKey,
};
use soroban_sdk::{
    testutils::{Address as _, Events as _},
    Address, Bytes, BytesN, Env,
};

use smart_wallet::{
    AuthPayload, SignaturePayload, SmartWalletContract, SmartWalletContractClient, SmartWalletError,
};

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
        let encoded = secret.public_key().to_encoded_point(false);
        let mut pk = [0u8; 65];
        pk.copy_from_slice(encoded.as_bytes());
        TestKey {
            signing_key,
            public_key_bytes: pk,
        }
    }

    fn sign(&self, raw: &[u8; 40]) -> [u8; 64] {
        let sig: Signature = self.signing_key.sign(raw);
        let normalized = sig.normalize_s().unwrap_or(sig);
        let mut out = [0u8; 64];
        out.copy_from_slice(&normalized.to_bytes());
        out
    }
}

fn fake_cred_id(env: &Env, seed: u8) -> BytesN<16> {
    let mut raw = [0u8; 16];
    raw[0] = seed;
    BytesN::from_array(env, &raw)
}

fn raw_payload_bytes(nonce: u64, op_hash: &[u8; 32]) -> [u8; 40] {
    let mut data = [0u8; 40];
    data[..8].copy_from_slice(&nonce.to_le_bytes());
    data[8..].copy_from_slice(op_hash);
    data
}

fn setup_with_key<'a>(env: &'a Env) -> (SmartWalletContractClient<'a>, Address, TestKey, BytesN<16>) {
    let key = TestKey::new();
    let contract_id = env.register_contract(None, SmartWalletContract);
    let client = SmartWalletContractClient::new(env, &contract_id);
    let owner = Address::generate(env);
    let cred_id = fake_cred_id(env, 42);

    client.initialize(
        &owner,
        &cred_id,
        &BytesN::from_array(env, &key.public_key_bytes),
        &Bytes::from_slice(env, b"Secured Phone"),
    );

    (client, owner, key, cred_id)
}

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
        Err(Err(invoke_err)) => panic!("check_auth invocation failed: {:?}", invoke_err),
    }
}

#[test]
fn test_owner_can_lock_and_unlock_wallet() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, owner, _, _) = setup_with_key(&env);

    assert_eq!(client.is_locked(), false);

    // Lock wallet as owner
    client.lock_wallet(&owner);
    assert_eq!(client.is_locked(), true);

    let events = env.events().all();
    assert!(events.len() >= 2);

    // Unlock wallet as owner
    client.unlock_wallet(&owner);
    assert_eq!(client.is_locked(), false);

    let events = env.events().all();
    assert!(events.len() >= 3);
}

#[test]
fn test_guardian_can_lock_and_unlock_wallet() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _owner, _, _) = setup_with_key(&env);

    let guardian = Address::generate(&env);
    client.set_guardian(&guardian);

    assert_eq!(client.is_locked(), false);

    // Guardian locks wallet
    client.lock_wallet(&guardian);
    assert_eq!(client.is_locked(), true);

    // Guardian unlocks wallet
    client.unlock_wallet(&guardian);
    assert_eq!(client.is_locked(), false);
}

#[test]
fn test_unauthorized_address_cannot_lock_or_unlock() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _owner, _, _) = setup_with_key(&env);

    let attacker = Address::generate(&env);

    let res = client.try_lock_wallet(&attacker);
    assert_eq!(res, Err(Ok(SmartWalletError::Unauthorized)));

    let res = client.try_unlock_wallet(&attacker);
    assert_eq!(res, Err(Ok(SmartWalletError::Unauthorized)));
}

#[test]
fn test_locked_wallet_rejects_check_auth() {
    let env = Env::default();
    let (client, owner, key, cred_id) = setup_with_key(&env);

    let nonce = client.get_nonce();
    let op_hash_raw = [0x5au8; 32];
    let raw_payload = raw_payload_bytes(nonce, &op_hash_raw);
    let sig_bytes = key.sign(&raw_payload);

    let auth_payload = AuthPayload {
        credential_id: cred_id.clone(),
        signed: SignaturePayload {
            nonce,
            operation_hash: BytesN::from_array(&env, &op_hash_raw),
        },
        signature: BytesN::from_array(&env, &sig_bytes),
    };

    // Lock the wallet
    env.mock_all_auths();
    client.lock_wallet(&owner);
    assert_eq!(client.is_locked(), true);

    // Attempt check_auth while locked
    let err = check_auth_shim(&env, &client, auth_payload.clone()).unwrap_err();
    assert_eq!(err, SmartWalletError::WalletLocked);

    // Unlock wallet and verify auth succeeds now
    client.unlock_wallet(&owner);
    assert_eq!(client.is_locked(), false);

    check_auth_shim(&env, &client, auth_payload).unwrap();
    assert_eq!(client.get_nonce(), 1);
}

#[test]
fn test_recovery_automatically_clears_locked_state() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, owner, _, _) = setup_with_key(&env);

    let guardian = Address::generate(&env);
    client.set_guardian(&guardian);

    // Lock the wallet
    client.lock_wallet(&owner);
    assert_eq!(client.is_locked(), true);

    // Guardian initiates recovery
    let new_cred_id = fake_cred_id(&env, 99);
    let new_key = TestKey::new();
    client.recover_wallet(
        &new_cred_id,
        &BytesN::from_array(&env, &new_key.public_key_bytes),
        &Bytes::from_slice(&env, b"Replacement Key"),
    );

    // Wallet is automatically unlocked after recovery
    assert_eq!(client.is_locked(), false);
}

#[test]
fn test_lock_uninitialized_returns_error() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SmartWalletContract);
    let client = SmartWalletContractClient::new(&env, &contract_id);
    let caller = Address::generate(&env);

    let res = client.try_lock_wallet(&caller);
    assert_eq!(res, Err(Ok(SmartWalletError::NotInitialized)));

    let res = client.try_is_locked();
    assert_eq!(res, Err(Ok(SmartWalletError::NotInitialized)));
}
