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
