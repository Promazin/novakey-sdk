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
