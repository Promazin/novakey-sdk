//! Account recovery via trusted guardian.
//!
//! Enables social recovery if a user loses all registered passkeys / devices.
//! The guardian replaces all registered credentials with a new passkey and advances
//! the nonce to invalidate any unexecuted signatures.

use soroban_sdk::{Bytes, BytesN, Env};

use crate::{
    error::SmartWalletError,
    events,
    registration,
    storage,
    types::Credential,
};

/// Execute account recovery.
///
/// Must be authorized by the configured guardian.
/// Replaces all existing credentials with `new_credential_id`.
pub fn recover_wallet(
    env: &Env,
    new_credential_id: &BytesN<16>,
    new_public_key: &BytesN<65>,
    new_label: &Bytes,
) -> Result<(), SmartWalletError> {
    let guardian = storage::get_guardian(env).ok_or(SmartWalletError::GuardianNotSet)?;
    guardian.require_auth();

    registration::validate_public_key(new_public_key)?;

    if new_label.len() as usize > registration::MAX_LABEL_BYTES {
        return Err(SmartWalletError::LabelTooLong);
    }

    // Deregister/remove all existing credentials to revoke compromised or lost devices.
    let old_list = storage::load_credential_ids(env);
    for id in old_list.ids.iter() {
        storage::remove_credential(env, &id);
        events::credential_removed(env, &id);
    }

    // Register new passkey as the sole credential
    let mut new_ids = soroban_sdk::Vec::new(env);
    new_ids.push_back(new_credential_id.clone());
    storage::save_credential_ids(env, &storage::CredentialIdList { ids: new_ids });

    let credential = Credential {
        public_key: new_public_key.clone(),
        label: new_label.clone(),
    };
    storage::save_credential(env, new_credential_id, &credential);
    storage::bump_credential_ttl(env, new_credential_id);
    events::credential_registered(env, new_credential_id, new_label);

    // Invalidate any previously signed intents by advancing the nonce
    let current_nonce = storage::get_nonce(env);
    storage::set_nonce(env, current_nonce.saturating_add(1));

    // Release emergency lock if it was active
    storage::set_locked(env, false);

    storage::bump_instance_ttl(env);
    events::wallet_recovered(env, &guardian, new_credential_id);

    Ok(())
}
