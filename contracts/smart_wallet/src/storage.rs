use soroban_sdk::{contracttype, Address, BytesN};

use crate::types::Credential;

/// Top-level storage keys for the smart wallet instance data.
#[contracttype]
pub enum DataKey {
    /// Whether this contract has been initialised.
    Initialized,
    /// The Stellar address of the wallet owner (set at init time).
    Owner,
    /// A registered credential keyed by its 16-byte CBOR credential ID.
    Credential(BytesN<16>),
    /// Ordered list of all registered credential IDs.
    CredentialIds,
    /// Monotonic nonce to prevent transaction replay.
    Nonce,
    /// Recovery guardian address allowed to reset credentials.
    Guardian,
}

/// Thin wrapper around a list of credential IDs so it can be stored as one
/// ledger entry and iterated cheaply.
#[contracttype]
#[derive(Clone)]
pub struct CredentialIdList {
    pub ids: soroban_sdk::Vec<BytesN<16>>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Storage helpers
// ──────────────────────────────────────────────────────────────────────────────

use soroban_sdk::Env;

/// Returns `true` if the wallet has been initialised.
pub fn is_initialized(env: &Env) -> bool {
    env.storage()
        .instance()
        .has(&DataKey::Initialized)
}

/// Mark the wallet as initialised. Panics if called twice.
pub fn set_initialized(env: &Env) {
    env.storage()
        .instance()
        .set(&DataKey::Initialized, &true);
}

/// Persist the owner address.
pub fn set_owner(env: &Env, owner: &Address) {
    env.storage()
        .instance()
        .set(&DataKey::Owner, owner);
}

/// Retrieve the owner address. Returns `None` if not set.
pub fn get_owner(env: &Env) -> Option<Address> {
    env.storage()
        .instance()
        .get(&DataKey::Owner)
}

// ── Credential store ──────────────────────────────────────────────────────────

/// Persist a credential keyed by its ID.
pub fn save_credential(env: &Env, credential_id: &BytesN<16>, credential: &Credential) {
    env.storage()
        .persistent()
        .set(&DataKey::Credential(credential_id.clone()), credential);
}

/// Retrieve a credential by its ID. Returns `None` if not found.
pub fn load_credential(env: &Env, credential_id: &BytesN<16>) -> Option<Credential> {
    env.storage()
        .persistent()
        .get(&DataKey::Credential(credential_id.clone()))
}

/// Remove a credential by its ID.
pub fn remove_credential(env: &Env, credential_id: &BytesN<16>) {
    env.storage()
        .persistent()
        .remove(&DataKey::Credential(credential_id.clone()));
}

/// Load the list of registered credential IDs (empty list if none yet).
pub fn load_credential_ids(env: &Env) -> CredentialIdList {
    env.storage()
        .instance()
        .get(&DataKey::CredentialIds)
        .unwrap_or(CredentialIdList {
            ids: soroban_sdk::Vec::new(env),
        })
}

/// Persist the credential ID list.
pub fn save_credential_ids(env: &Env, list: &CredentialIdList) {
    env.storage()
        .instance()
        .set(&DataKey::CredentialIds, list);
}

// ── Nonce ─────────────────────────────────────────────────────────────────────

/// Read the current nonce (defaults to 0 if never set).
pub fn get_nonce(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::Nonce)
        .unwrap_or(0u64)
}

/// Persist the nonce.
pub fn set_nonce(env: &Env, nonce: u64) {
    env.storage().instance().set(&DataKey::Nonce, &nonce);
}

// ── Guardian ──────────────────────────────────────────────────────────────────

/// Set the recovery guardian address.
pub fn set_guardian(env: &Env, guardian: &Address) {
    env.storage().instance().set(&DataKey::Guardian, guardian);
}

/// Retrieve the recovery guardian address.
pub fn get_guardian(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::Guardian)
}

/// Remove the recovery guardian.
pub fn remove_guardian(env: &Env) {
    env.storage().instance().remove(&DataKey::Guardian);
}

// ── Ledger TTL management ─────────────────────────────────────────────────────
//
// Soroban charges rent based on how long entries live. We bump the TTL of all
// persistent entries on every successful auth so the wallet stays alive as
// long as it is actively used.

/// Minimum ledger sequences a persistent credential entry must survive.
/// ~30 days at ~6 s/ledger on Stellar.
const CREDENTIAL_MIN_TTL: u32 = 432_000;

/// Bump the TTL of a credential entry so it survives at least `CREDENTIAL_MIN_TTL`
/// more ledger sequences from now.
pub fn bump_credential_ttl(env: &Env, credential_id: &BytesN<16>) {
    env.storage().persistent().extend_ttl(
        &DataKey::Credential(credential_id.clone()),
        CREDENTIAL_MIN_TTL,
        CREDENTIAL_MIN_TTL,
    );
}

/// Bump the TTL of instance storage (owner, nonce, credential ID list).
/// Called on every successful transaction so the wallet never expires while
/// in active use.
pub fn bump_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(CREDENTIAL_MIN_TTL, CREDENTIAL_MIN_TTL);
}
