use soroban_sdk::{Address, BytesN, Env, Symbol};

/// Emitted when a new smart wallet is deployed.
///
/// Topics: `("wallet_deployed", owner)`
/// Data: `(wallet_address, credential_id)`
pub fn wallet_deployed(
    env: &Env,
    owner: &Address,
    wallet: &Address,
    credential_id: &BytesN<16>,
) {
    let topics = (Symbol::new(env, "wallet_deployed"), owner.clone());
    env.events().publish(topics, (wallet.clone(), credential_id.clone()));
}

/// Emitted when the smart wallet WASM hash is updated by admin.
///
/// Topics: `("wasm_updated", admin)`
/// Data: `new_wasm_hash`
pub fn wasm_hash_updated(env: &Env, admin: &Address, new_wasm_hash: &BytesN<32>) {
    let topics = (Symbol::new(env, "wasm_updated"), admin.clone());
    env.events().publish(topics, new_wasm_hash.clone());
}
