use soroban_sdk::{Bytes, BytesN, Env, Symbol};

/// Emitted when a new passkey credential is registered.
///
/// Topics: `("credential_registered", credential_id)`
/// Data: `label`
pub fn credential_registered(env: &Env, credential_id: &BytesN<16>, label: &Bytes) {
    let topics = (Symbol::new(env, "credential_registered"), credential_id.clone());
    env.events().publish(topics, label.clone());
}

/// Emitted when a passkey credential is deregistered.
///
/// Topics: `("credential_removed", credential_id)`
/// Data: `()`
pub fn credential_removed(env: &Env, credential_id: &BytesN<16>) {
    let topics = (Symbol::new(env, "credential_removed"), credential_id.clone());
    env.events().publish(topics, ());
}

/// Emitted when an authentication payload is successfully verified and nonce advances.
///
/// Topics: `("auth_success", credential_id)`
/// Data: `(nonce, operation_hash)`
pub fn auth_success(env: &Env, credential_id: &BytesN<16>, nonce: u64, op_hash: &BytesN<32>) {
    let topics = (Symbol::new(env, "auth_success"), credential_id.clone());
    env.events().publish(topics, (nonce, op_hash.clone()));
}

/// Emitted when a guardian is configured.
///
/// Topics: `("guardian_set", guardian)`
/// Data: `()`
pub fn guardian_set(env: &Env, guardian: &soroban_sdk::Address) {
    let topics = (Symbol::new(env, "guardian_set"), guardian.clone());
    env.events().publish(topics, ());
}

/// Emitted when a guardian is removed.
///
/// Topics: `("guardian_removed", ())`
/// Data: `()`
pub fn guardian_removed(env: &Env) {
    let topics = (Symbol::new(env, "guardian_removed"), ());
    env.events().publish(topics, ());
}

/// Emitted when wallet recovery is executed by guardian.
///
/// Topics: `("wallet_recovered", guardian)`
/// Data: `new_credential_id`
pub fn wallet_recovered(env: &Env, guardian: &soroban_sdk::Address, new_credential_id: &BytesN<16>) {
    let topics = (Symbol::new(env, "wallet_recovered"), guardian.clone());
    env.events().publish(topics, new_credential_id.clone());
}

/// Emitted when a passkey credential's human-readable label is updated.
///
/// Topics: `("credential_label_updated", credential_id)`
/// Data: `new_label`
pub fn credential_label_updated(env: &Env, credential_id: &BytesN<16>, new_label: &Bytes) {
    let topics = (
        Symbol::new(env, "credential_label_updated"),
        credential_id.clone(),
    );
    env.events().publish(topics, new_label.clone());
}

/// Emitted when wallet ownership is transferred to a new address.
///
/// Topics: `("ownership_transferred", old_owner)`
/// Data: `new_owner`
pub fn ownership_transferred(
    env: &Env,
    old_owner: &soroban_sdk::Address,
    new_owner: &soroban_sdk::Address,
) {
    let topics = (Symbol::new(env, "ownership_transferred"), old_owner.clone());
    env.events().publish(topics, new_owner.clone());
}

/// Emitted when the wallet contract WASM binary is upgraded by the owner.
///
/// Topics: `("wallet_upgraded", owner)`
/// Data: `new_wasm_hash`
pub fn wallet_upgraded(
    env: &Env,
    owner: &soroban_sdk::Address,
    new_wasm_hash: &BytesN<32>,
) {
    let topics = (Symbol::new(env, "wallet_upgraded"), owner.clone());
    env.events().publish(topics, new_wasm_hash.clone());
}

/// Emitted when the wallet is placed under emergency lock.
///
/// Topics: `("wallet_locked", caller)`
/// Data: `()`
pub fn wallet_locked(env: &Env, caller: &soroban_sdk::Address) {
    let topics = (Symbol::new(env, "wallet_locked"), caller.clone());
    env.events().publish(topics, ());
}

/// Emitted when the emergency lock is released.
///
/// Topics: `("wallet_unlocked", caller)`
/// Data: `()`
pub fn wallet_unlocked(env: &Env, caller: &soroban_sdk::Address) {
    let topics = (Symbol::new(env, "wallet_unlocked"), caller.clone());
    env.events().publish(topics, ());
}
