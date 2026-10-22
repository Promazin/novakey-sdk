use soroban_sdk::{contracttype, Address, BytesN, Env};

/// Top-level storage keys for the factory.
#[contracttype]
pub enum FactoryDataKey {
    /// Whether the factory has been initialised.
    Initialized,
    /// The SHA-256 WASM hash of the SmartWallet contract binary.
    WalletWasmHash,
    /// Administrator address allowed to upgrade the wallet WASM hash.
    Admin,
    /// Deployed wallet address keyed by credential ID.
    WalletAddress(BytesN<16>),
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn is_initialized(env: &Env) -> bool {
    env.storage()
        .instance()
        .has(&FactoryDataKey::Initialized)
}

pub fn set_initialized(env: &Env) {
    env.storage()
        .instance()
        .set(&FactoryDataKey::Initialized, &true);
}

pub fn set_wasm_hash(env: &Env, hash: &BytesN<32>) {
    env.storage()
        .instance()
        .set(&FactoryDataKey::WalletWasmHash, hash);
}

pub fn get_wasm_hash(env: &Env) -> Option<BytesN<32>> {
    env.storage()
        .instance()
        .get(&FactoryDataKey::WalletWasmHash)
}

pub fn set_admin(env: &Env, admin: &Address) {
    env.storage()
        .instance()
        .set(&FactoryDataKey::Admin, admin);
}

pub fn get_admin(env: &Env) -> Option<Address> {
    env.storage()
        .instance()
        .get(&FactoryDataKey::Admin)
}

pub fn save_wallet_address(env: &Env, credential_id: &BytesN<16>, address: &Address) {
    env.storage()
        .persistent()
        .set(&FactoryDataKey::WalletAddress(credential_id.clone()), address);
}

pub fn load_wallet_address(env: &Env, credential_id: &BytesN<16>) -> Option<Address> {
    env.storage()
        .persistent()
        .get(&FactoryDataKey::WalletAddress(credential_id.clone()))
}

/// Minimum TTL for wallet address entries (~30 days).
const WALLET_MIN_TTL: u32 = 432_000;

pub fn bump_wallet_ttl(env: &Env, credential_id: &BytesN<16>) {
    env.storage().persistent().extend_ttl(
        &FactoryDataKey::WalletAddress(credential_id.clone()),
        WALLET_MIN_TTL,
        WALLET_MIN_TTL,
    );
}

pub fn bump_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(WALLET_MIN_TTL, WALLET_MIN_TTL);
}
